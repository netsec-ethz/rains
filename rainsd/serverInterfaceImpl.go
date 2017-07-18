package rainsd

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/cache"
	setDataStruct "github.com/netsec-ethz/rains/utils/set"

	log "github.com/inconshreveable/log15"
)

type connAndCapabilitList struct {
	Connections    []net.Conn
	CapabilityList *[]rainslib.Capability
}

/*
 *	Connection cache implementation
 *  FIXME CFE currently this cache only supports one connection per destination
 *  Otherwise we would have a race condition and delete statement would be more complicated
 */
type connectionCacheImpl struct {
	cache *cache.Cache
}

//AddConnection adds conn to the cache. If the cache is full the least recently used connection is removed.
func (c *connectionCacheImpl) AddConnection(conn net.Conn) bool {
	entry := connAndCapabilitList{Connections: []net.Conn{conn}}
	return c.cache.Add(&entry, false, "", conn.RemoteAddr().Network(), conn.RemoteAddr().String())
}

//AddCapability adds capabilities to the destAddr entry. It returns false if there is no entry
//in the cache for dstAddr
func (c *connectionCacheImpl) AddCapabilityList(dstAddr rainslib.ConnInfo, capabilities *[]rainslib.Capability) bool {
	network := ""
	switch dstAddr.Type {
	case rainslib.TCP:
		network = dstAddr.TCPAddr.Network()
	default:
		log.Warn("Unsupported network address type", "type", dstAddr.Type)
		return false
	}
	if entry, ok := c.cache.Get("", network, dstAddr.String()); ok {
		if entry, ok := entry.(*connAndCapabilitList); ok {
			entry.CapabilityList = capabilities
			return true
		}
		log.Warn("connectionCache contained element of wrong type. expected=*connAndCapabilitList",
			"actual", fmt.Sprintf("%T", entry))
	}
	return false
}

//GetConnection returns one cached connection to dstAddr
func (c *connectionCacheImpl) GetConnection(dstAddr rainslib.ConnInfo) ([]net.Conn, bool) {
	switch dstAddr.Type {
	case rainslib.TCP:
		if v, ok := c.cache.Get("", dstAddr.TCPAddr.Network(), dstAddr.TCPAddr.String()); ok {
			if val, ok := v.(net.Conn); ok {
				return []net.Conn{val}, true
			}
			log.Warn("Cache entry is not of type net.Conn", "type", fmt.Sprintf("%T", v))
		}
	default:
		log.Warn("Unsupported network address type", "type", dstAddr.Type)
	}
	return nil, false
}

//Delete closes conn and removes it from the cache
func (c *connectionCacheImpl) CloseAndRemoveConnection(conn net.Conn) bool {
	conn.Close()
	return c.cache.Remove("", conn.RemoteAddr().Network(), conn.RemoteAddr().String())
}

func (c *connectionCacheImpl) Len() int {
	return c.cache.Len()
}

/*
 *	Capability cache implementation
 */
type capabilityCacheImpl struct {
	capabilityMap *cache.Cache
}

func (c *capabilityCacheImpl) Add(capabilities []rainslib.Capability) {
	//FIXME CFE take a SHA-256 hash of the CBOR byte stream derived from normalizing such an array by sorting it in lexicographically increasing order,
	//then serializing it and add it to the cache
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i] < capabilities[j] })
	cs := []byte{}
	for _, c := range capabilities {
		cs = append(cs, []byte(c)...)
	}
	hash := sha256.Sum256(cs)
	c.capabilityMap.Add(&capabilities, false, "", string(hash[:]))
}

func (c *capabilityCacheImpl) Get(hash []byte) (*[]rainslib.Capability, bool) {
	if v, ok := c.capabilityMap.Get("", string(hash)); ok {
		if val, ok := v.(*[]rainslib.Capability); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type *[]rainslib.Capability",
			"actualType", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c *capabilityCacheImpl) Len() int {
	return c.Len()
}

/*
 * Key cache implementation
 */
type keyCacheImpl struct {
	cache *cache.Cache
}

//Add adds the public key to the cash.
//Returns true if the given public key was successfully added. If it was not possible to add the key it return false.
//If the cache is full it removes all public keys from a keyCacheKey entry according to least recently used
//The cache makes sure that only a small limited amount of public keys (e.g. 3) can be stored associated with a keyCacheKey
//If the internal flag is set, this key will only be removed after it expired.
func (c *keyCacheImpl) Add(key keyCacheKey, value rainslib.PublicKey, internal bool) bool {
	//TODO add an getOrAdd method to the cache (locking must then be changed.)
	list := &pubKeyList{maxElements: 3, keys: list.New()}
	c.cache.Add(list, internal, "", key.zone, key.keyAlgo.String())
	v, ok := c.cache.Get("", key.zone, key.keyAlgo.String())
	if !ok {
		return false
	}
	if list, ok := v.(*pubKeyList); ok {
		list.Add(value)
		return true
	}
	log.Error(fmt.Sprintf("Element in cache is not of type *pubKeyList. Got type=%T", v))
	return false
}

//Get returns a valid public key matching the given keyCacheKey. It returns false if there exists no valid public key in the cache.
func (c *keyCacheImpl) Get(key keyCacheKey) (rainslib.PublicKey, bool) {
	v, ok := c.cache.Get("", key.zone, key.keyAlgo.String())
	if !ok {
		return rainslib.PublicKey{}, false
	}
	list := v.(publicKeyList)
	k, ok := list.Get() //The returned key is guaranteed to be valid
	if !ok {
		return rainslib.PublicKey{}, false
	}
	return k, true
}

//RemoveExpiredKeys deletes a public key value pair from the cache if it is expired
func (c *keyCacheImpl) RemoveExpiredKeys() {
	keys := c.cache.Keys()
	for _, key := range keys {
		v, ok := c.cache.Get(key[0], key[1])
		if ok {
			list := v.(publicKeyList)
			list.RemoveExpiredKeys()
		}
	}
}

//pubKeyList contains some public keys which can be modified concurrently. There are at most maxElements in the list.
type pubKeyList struct {
	//maxElements are the maximal number of elements in the list
	maxElements int
	//mux must always be called when accessing keys list.
	mux sync.RWMutex
	//keys contains public keys
	keys *list.List
}

//Add adds a public key to the list. If specified maximal list length is reached it removes the least recently used element.
func (l *pubKeyList) Add(key rainslib.PublicKey) {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.keys.PushFront(key)
	if l.keys.Len() > l.maxElements {
		l.keys.Remove(l.keys.Back())
	}
}

//Get returns the first valid public key in the list. Returns false if there is no valid public key.
func (l *pubKeyList) Get() (rainslib.PublicKey, bool) {
	l.mux.RLock()
	defer l.mux.RUnlock()
	for e := l.keys.Front(); e != nil; e = e.Next() {
		key := e.Value.(rainslib.PublicKey)
		if key.ValidSince <= time.Now().Unix() && key.ValidUntil > time.Now().Unix() {
			l.keys.MoveToFront(e)
			return key, true
		}
	}
	return rainslib.PublicKey{}, false
}

//RemoveExpiredKeys deletes all expired keys from the list.
func (l *pubKeyList) RemoveExpiredKeys() {
	l.mux.Lock()
	defer l.mux.Unlock()
	for e := l.keys.Front(); e != nil; e = e.Next() {
		key := e.Value.(rainslib.PublicKey)
		if key.ValidUntil < time.Now().Unix() {
			l.keys.Remove(e)
		}
	}
}

/*
 * Pending signature cache implementation
 * We have a hierarchical locking system. We first lock the cache to get a pointer to a set data structure. Then we release the lock on the cache and for
 * operations on the set data structure we use a separate lock.
 * We store the elementCount (number of sections in the pendingSignatureCacheImpl) separate, as each cache entry can have several sections in the set data structure.
 * When we want to update elementCount we must lock using elemCountLock. This lock must never be held when doing a change to the the cache or the set data structure.
 * It can happen that some sections get dropped. This is the case when the cache is full or when we add a section to the set while another go routine deletes the pointer to that
 * set as it was empty before. The second case is expected to occur rarely.
 */
type pendingSignatureCacheImpl struct {
	cache        *cache.Cache
	maxElements  uint
	elementCount uint
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the set data structure.
	//TODO CFE take both mutex together, here and cache
	elemCountLock sync.RWMutex
}

//Add adds a section together with a validity to the cache. Returns true if there is not yet a pending query for this context and zone
//If the cache is full it removes all section stored with the least recently used <context, zone> tuple.
func (c *pendingSignatureCacheImpl) Add(context, zone string, value pendingSignatureCacheValue) bool {
	log.Debug("Add value to pending signature cache", "context", context, "zone", zone, "value", value)
	set := setDataStruct.New()
	set.Add(value)
	ok := c.cache.Add(set, false, context, zone)
	if ok {
		updateCount(c)
		handleCacheSize(c)
		return true
	}
	log.Debug("There is already a set in the cache, get it and add value.")
	v, ok := c.cache.Get(context, zone)
	if ok {
		val, ok := v.(setContainer)
		if ok {
			ok := val.Add(value)
			if ok {
				updateCount(c)
				handleCacheSize(c)
				return false
			}
			log.Warn("List was closed but cache entry was not yet deleted. This case must be rare!")
			return false
		}
		log.Error(fmt.Sprintf("Cache element was not of type container. Got:%T", v))
		return false
	}
	//cache entry was deleted in the meantime. Retry
	log.Warn("Cache entry was delete between, trying to add new and getting the existing one. This case must be rare!")
	return c.Add(context, zone, value)
}

//updateCount increases the element count by one
func updateCount(c *pendingSignatureCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
}

//handleCacheSize deletes all sections from the least recently used cache entry if it exceeds the cache siz.
func handleCacheSize(c *pendingSignatureCacheImpl) {
	if c.elementCount > c.maxElements {
		key, _ := c.cache.GetLeastRecentlyUsedKey()
		c.GetAllAndDelete(key[0], key[1])
	}
}

//GetAllAndDelete returns true and all valid sections associated with the given context and zone if there are any. Otherwise false.
//We simultaneously obtained all elements and close the set data structure. Then we remove the entry from the cache. If in the meantime an Add operation happened,
//then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
func (c *pendingSignatureCacheImpl) GetAllAndDelete(context, zone string) ([]sectionWithSigSender, bool) {
	sections := []sectionWithSigSender{}
	deleteCount := uint(0)
	v, ok := c.cache.Get(context, zone)
	if !ok {
		return sections, false
	}
	if set, ok := v.(setContainer); ok {
		secs := set.GetAllAndDelete()
		deleteCount = uint(len(secs))
		c.cache.Remove(context, zone)
		for _, section := range secs {
			if s, ok := section.(pendingSignatureCacheValue); ok {
				if s.validUntil > time.Now().Unix() {
					sections = append(sections, s.sectionWSSender)
				} else {
					log.Info("section expired", "section", s.sectionWSSender, "validity", s.validUntil)
				}
			} else {
				log.Error(fmt.Sprintf("Cache element was not of type pendingSignatureCacheValue. Got:%T", section))
			}
		}

	} else {
		log.Error(fmt.Sprintf("Cache element was not of type container. Got:%T", v))
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
	return sections, len(sections) > 0
}

//RemoveExpiredSections goes through the cache and removes all expired sections. If for a given context and zone there is no section left it removes the entry from cache.
func (c *pendingSignatureCacheImpl) RemoveExpiredSections() {
	keys := c.cache.Keys()
	deleteCount := uint(0)
	for _, key := range keys {
		v, ok := c.cache.Get(key[0], key[1])
		if ok { //check if element is still contained
			set, ok := v.(setContainer)
			if ok { //check that cache element is a data container
				vals := set.GetAll()
				//check validity of all container elements and remove expired once
				allRemoved := true
				for _, val := range vals {
					v, ok := val.(pendingSignatureCacheValue)
					if ok {
						if v.validUntil < time.Now().Unix() {
							ok := set.Delete(val)
							if ok {
								deleteCount++
							}
						} else {
							allRemoved = false
						}
					} else {
						log.Error(fmt.Sprintf("set element was not of type pendingSignatureCacheValue. Got:%T", val))
					}
				}
				//remove entry from cache if non left. If one was added in the meantime do not delete it.
				if allRemoved {
					vals := set.GetAllAndDelete()
					if len(vals) == 0 {
						c.cache.Remove(key[0], key[1])
					} else {
						set := setDataStruct.New()
						for _, val := range vals {
							set.Add(val)
						}
						//FIXME CFE here another go routine could come in between. Add an update function to the cache.
						c.cache.Remove(key[0], key[1])
						c.cache.Add(set, false, key[0], key[1])
					}
				}
			} else {
				log.Error(fmt.Sprintf("Cache element was not of type container. Got:%T", v))
			}
		}
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
}

//Len returns the number of sections in the cache.
func (c *pendingSignatureCacheImpl) Len() int {
	c.elemCountLock.RLock()
	defer c.elemCountLock.RUnlock()
	return int(c.elementCount)
}

type elemAndValidTo struct {
	validUntil int64
	context    string
	zone       string
	name       string
	objType    rainslib.ObjectType
}

/*
 * Pending query cache implementation
 * We have a hierarchical locking system. We first lock the cache to get a pointer to a set data structure. Then we release the lock on the cache and for
 * operations on the set data structure we use a separate lock.
 * We store the elementCount (number of sections in the pendingQueryCacheImpl) separate, as each cache entry can have several querier infos in the set data structure.
 * When we want to update elementCount we must lock using elemCountLock. This lock must never be held when doing a change to the the cache or the set data structure.
 * It can happen that some sections get dropped. This is the case when the cache is full or when we add a section to the set while another go routine deletes the pointer to that
 * set as it was empty before. The second case is expected to occur rarely.
 */
type pendingQueryCacheImpl struct {
	//callBackCache stores to a given <context,zone,name,type> the query validity and connection information of the querier waiting for the answer.
	//It is used to avoid sending the same query multiple times to obtain the same information.
	callBackCache *cache.Cache
	maxElements   uint
	elementCount  uint
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the set data structure.
	elemCountLock sync.RWMutex

	//activeTokens contains all tokens of sent out queries to be able to find the peers asking for this information.
	activeTokens    map[[16]byte]elemAndValidTo
	activeTokenLock sync.RWMutex
}

//Add adds connection information together with a token and a validity to the cache.
//Returns true if cache does not contain a valid entry for context,zone,name,objType else return false
//If the cache is full it removes a pendingQueryCacheValue according to some metric.
func (c *pendingQueryCacheImpl) Add(context, zone, name string, objType []rainslib.ObjectType, value pendingQuerySetValue) (bool, rainslib.Token) {
	set := setDataStruct.New()
	set.Add(value)
	token := rainslib.GenerateToken()
	cacheValue := pendingQueryCacheValue{set: set, token: token}
	ok := c.callBackCache.Add(cacheValue, false, context, zone, name, fmt.Sprintf("%v", objType))
	if ok {
		c.activeTokenLock.Lock()
		c.activeTokens[token] = elemAndValidTo{
			context: context,
			zone:    zone,
			name:    name,
			//FIXME CFE allow multiple types
			objType:    objType[0],
			validUntil: value.validUntil,
		}
		c.activeTokenLock.Unlock()
		updatePendingQueryCount(c)
		handlePendingQueryCacheSize(c)
		return true, token
	}
	//there is already a set in the cache, get it and add value.
	v, ok := c.callBackCache.Get(context, zone, name, fmt.Sprintf("%v", objType))
	if ok {
		val, ok := v.(pendingQueryCacheValue)
		if ok {
			ok := val.set.Add(value)
			if ok {
				updatePendingQueryCount(c)
				handlePendingQueryCacheSize(c)
				return false, [16]byte{}
			}
			log.Warn("Set was closed but cache entry was not yet deleted. This case must be rare!")
			return false, [16]byte{}
		}
		log.Error(fmt.Sprintf("Cache element was not of type pendingQueryCacheValue. Got:%T", v))
		return false, [16]byte{}
	}
	//cache entry was deleted in the meantime. Retry
	log.Warn("Cache entry was delete between, trying to add new and getting the existing one. This case must be rare!")
	return c.Add(context, zone, name, objType, value)
}

//updatePendingQueryCount increases the element count by one
func updatePendingQueryCount(c *pendingQueryCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
}

//handlePendingQueryCacheSize deletes all sender infos from the least recently used cache entry if it exceeds the cache size
func handlePendingQueryCacheSize(c *pendingQueryCacheImpl) {
	c.elemCountLock.RLock()
	if c.elementCount > c.maxElements {
		c.elemCountLock.RUnlock()
		key, _ := c.callBackCache.GetLeastRecentlyUsedKey()
		v, ok := c.callBackCache.Get(key[0], key[1])
		if ok {
			if v, ok := v.(pendingQueryCacheValue); ok {
				c.GetAllAndDelete(v.token)
			}
		}
	} else {
		c.elemCountLock.RUnlock()
	}
}

//GetAllAndDelete returns true and all valid pendingQueryCacheValues associated with the given token if there are any. Otherwise false
//We remove the entry from the cache and from the activeToken map. Then we simultaneously obtained all elements from the set data structure and close it.
//If in the meantime an Add operation happened, then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
func (c *pendingQueryCacheImpl) GetAllAndDelete(token rainslib.Token) ([]pendingQuerySetValue, bool) {
	sendInfos := []pendingQuerySetValue{}
	deleteCount := uint(0)
	c.activeTokenLock.RLock()
	v, ok := c.activeTokens[token]
	c.activeTokenLock.RUnlock()
	if !ok || v.validUntil < time.Now().Unix() {
		log.Debug("Token not in cache or expired", "token", token, "Now", time.Now(), "ValidUntil", time.Unix(v.validUntil, 0))
		return sendInfos, false
	}
	val, ok := c.callBackCache.Get(v.context, v.zone, v.name, v.objType.String())
	if !ok {
		log.Info("For context,zone,name,type there is no entry in the cache.", "value", val)
		return sendInfos, false
	}
	if cval, ok := val.(pendingQueryCacheValue); ok {
		c.callBackCache.Remove(v.context, v.zone, v.name, v.objType.String())
		c.activeTokenLock.Lock()
		delete(c.activeTokens, token)
		c.activeTokenLock.RUnlock()
		queriers := cval.set.GetAllAndDelete()
		deleteCount = uint(len(queriers))
		for _, querier := range queriers {
			if q, ok := querier.(pendingQuerySetValue); ok {
				if q.validUntil > time.Now().Unix() {
					sendInfos = append(sendInfos, q)
				} else {
					log.Info("query expired.", "sender", q.connInfo, "token", q.token)
				}
			} else {
				log.Error(fmt.Sprintf("Cache element was not of type pendingQuerySetValue. Got:%T", querier))
			}
		}

	} else {
		log.Error(fmt.Sprintf("Cache not of type pendingQueryCacheValue. Got:%T", v))
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
	return sendInfos, len(sendInfos) > 0
}

//RemoveExpiredValues goes through the cache and removes all expired values and tokens. If for a given context and zone there is no value left it removes the entry from cache.
func (c *pendingQueryCacheImpl) RemoveExpiredValues() {
	//Delete all expired tokens
	c.activeTokenLock.Lock()
	for key, val := range c.activeTokens {
		if val.validUntil < time.Now().Unix() {
			delete(c.activeTokens, key)
			c.callBackCache.Remove(val.context, val.zone, val.name, val.objType.String())
		}
	}
	c.activeTokenLock.Unlock()
	//Delete expired received queries.
	keys := c.callBackCache.Keys()
	deleteCount := uint(0)
	for _, key := range keys {
		v, ok := c.callBackCache.Get(key[0], key[1])
		if ok { //check if element is still contained
			cval, ok := v.(pendingQueryCacheValue)
			if ok { //check that cache element is a pendingQueryCacheValue
				vals := cval.set.GetAll()
				//check validity of all container elements and remove expired once
				allRemoved := true
				for _, val := range vals {
					v, ok := val.(pendingQuerySetValue)
					if ok {
						if v.validUntil < time.Now().Unix() {
							ok := cval.set.Delete(val)
							if ok {
								deleteCount++
							}
						} else {
							allRemoved = false
						}
					} else {
						log.Error(fmt.Sprintf("set element was not of type pendingQuerySetValue. Got:%T", val))
					}
				}
				//remove entry from cache if non left. If one was added in the meantime do not delete it.
				if allRemoved {
					vals := cval.set.GetAllAndDelete()
					if len(vals) == 0 {
						c.callBackCache.Remove(key[0], key[1])
						c.activeTokenLock.Lock()
						delete(c.activeTokens, cval.token)
						c.activeTokenLock.RUnlock()
					} else {
						set := setDataStruct.New()
						for _, val := range vals {
							set.Add(val)
						}
						//FIXME CFE here another go routine could come in between. Add an update function to the cache.
						c.callBackCache.Remove(key[0], key[1])
						c.callBackCache.Add(set, false, key[0], key[1])
					}
				}
			} else {
				log.Error(fmt.Sprintf("Cache element was not of type pendingQueryCacheValue. Got:%T", v))
			}
		}
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
}

//Len returns the number of elements in the cache.
func (c *pendingQueryCacheImpl) Len() int {
	c.elemCountLock.RLock()
	defer c.elemCountLock.RUnlock()
	return int(c.elementCount)
}

/*
 * negative assertion implementation
 * We have a hierarchical locking system. We first lock the cache to get a pointer to a data structure which can efficiently process range queries (e.g. interval tree).
 * Then we release the lock on the cache and for operations on the set data structure we use a separate lock.
 * We store the elementCount (number of sections in the negativeAssertionCacheImpl) separate, as each cache entry can have several sections in the data structure.
 * When we want to update elementCount we must lock using elemCountLock. This lock must never be held when doing a change to the the cache or the underlying data structure.
 * It can happen that some sections get dropped. This is the case when the cache is full or when we add a section to the set while another go routine deletes the pointer to that
 * set as it was empty before. The second case is expected to occur rarely.
 */
type negativeAssertionCacheImpl struct {
	cache        *cache.Cache
	maxElements  uint
	elementCount uint
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the underlying data structure.
	elemCountLock sync.RWMutex
}

//Add adds a shard or zone together with a validity to the cache.
//Returns true if value was added to the cache.
//If the cache is full it removes an external negativeAssertionCacheValue according to some metric.
func (c *negativeAssertionCacheImpl) Add(context, zone string, internal bool, value negativeAssertionCacheValue) bool {
	//TODO add an getOrAdd method to the cache (locking must then be changed.)
	//TODO CFE replace sectionList with interval tree
	l := &sectionList{list: list.New()}
	l.Add(value)
	ok := c.cache.Add(l, internal, context, zone)
	if ok {
		updateNegElementCount(c)
		handleNegElementCacheSize(c)
		return true
	}
	//there is already a set in the cache, get it and add value.
	v, ok := c.cache.Get(context, zone)
	if ok {
		val, ok := v.(rangeQueryDataStruct)
		if ok {
			if ok := val.Add(value); ok {
				updateNegElementCount(c)
				handleNegElementCacheSize(c)
				return true
			}
			return false //element is already contained
		}
		log.Error(fmt.Sprintf("Cache entry is not of type rangeQueryDataStruct. Got=%T", v))
		return false
	}
	//cache entry was deleted in the meantime. Retry
	log.Warn("Cache entry was delete between, trying to add new and getting the existing one. This case must be rare!")
	return c.Add(context, zone, internal, value)
}

//updateNegElementCount increases the element count by one
func updateNegElementCount(c *negativeAssertionCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
}

//handleNegElementCacheSize  deletes all intervals from the least recently used cache entry if it exceeds the cache size
func handleNegElementCacheSize(c *negativeAssertionCacheImpl) {
	if c.elementCount > c.maxElements {
		key, _ := c.cache.GetLeastRecentlyUsedKey()
		v, ok := c.cache.Get(key[0], key[1])
		if ok {
			//FIXME CFE another go routine might also have a pointer to the data structure behind this entry. Then the count might be off...
			c.cache.Remove(key[0], key[1])
			v, _ := v.(rangeQueryDataStruct).Get(rainslib.TotalInterval{})
			c.elemCountLock.Lock()
			c.elementCount -= uint(len(v))
			c.elemCountLock.Unlock()
		}
	}
}

//Get returns true and the shortest sections with the longest validity of a given context and zone containing the name if there exists one. Otherwise false is returned
func (c *negativeAssertionCacheImpl) Get(context, zone string, interval rainslib.Interval) (rainslib.MessageSectionWithSig, bool) {
	sections, ok := c.GetAll(context, zone, interval)
	if ok {
		//TODO CFE return shortest shard, how to find out how large a shard is, store number of assertions to it?
		//TODO CFE check in shortest shard: if interval.Begin() == interval.End() -> if assertion is contained and if so return assertion.
		//(could have been evicted from assertionsCache)
		return sections[0], true
	}
	return nil, false
}

//GetAll returns true and all sections of a given context and zone which intersect with the given Range if there is at least one. Otherwise false is returned
//if beginRange and endRange are an empty string then the zone and all shards of that context and zone are returned
func (c *negativeAssertionCacheImpl) GetAll(context, zone string, interval rainslib.Interval) ([]rainslib.MessageSectionWithSig, bool) {
	v, ok := c.cache.Get(context, zone)
	if !ok {
		return nil, false
	}
	if rq, ok := v.(rangeQueryDataStruct); ok {
		sections := []rainslib.MessageSectionWithSig{}
		if intervals, ok := rq.Get(interval); ok && len(intervals) > 0 {
			for _, element := range intervals {
				if val, ok := element.(negativeAssertionCacheValue); ok && val.validUntil > time.Now().Unix() && val.validSince < time.Now().Unix() {
					sections = append(sections, val.section)
				}
			}
			return sections, true
		}
		return nil, false
	}
	log.Error(fmt.Sprintf("Cache entry is not of type rangeQueryDataStruct. got=%T", v))
	return nil, false
}

//Len returns the number of elements in the cache.
func (c *negativeAssertionCacheImpl) Len() int {
	c.elemCountLock.RLock()
	defer c.elemCountLock.RUnlock()
	return int(c.elementCount)
}

//RemoveExpiredValues goes through the cache and removes all expired values. If for a given context and zone there is no value left it removes the entry from cache.
func (c *negativeAssertionCacheImpl) RemoveExpiredValues() {
	keys := c.cache.Keys()
	deleteCount := uint(0)
	for _, key := range keys {
		v, ok := c.cache.Get(key[0], key[1])
		if ok { //check if element is still contained
			rq, ok := v.(rangeQueryDataStruct)
			if ok { //check that cache element is a range query data structure
				vals, ok := rq.Get(rainslib.TotalInterval{})
				allRemoved := true
				if ok {
					//check validity of all contained elements and remove expired once
					for _, val := range vals {
						v, ok := val.(negativeAssertionCacheValue)
						if ok {
							if v.validUntil < time.Now().Unix() {
								ok := rq.Delete(val)
								if ok {
									deleteCount++
								}
							} else {
								allRemoved = false
							}
						} else {
							log.Error(fmt.Sprintf("set element was not of type negativeAssertionCacheValue. Got:%T", val))
						}
					}
				}
				//remove entry from cache if non left. If one was added in the meantime do not delete it.
				if allRemoved {
					c.cache.Remove(key[0], key[1])
				}
			} else {
				log.Error(fmt.Sprintf("Cache element was not of type rangeQueryDataStruct. Got:%T", v))
			}
		}
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
}

//Remove deletes the cache entry for context and zone. Returns true if it was able to delete the entry
func (c *negativeAssertionCacheImpl) Remove(context, zone string) bool {
	v, ok := c.cache.Get(context, zone)
	c.cache.Remove(context, zone)
	if ok { //check if element is still contained
		rq, ok := v.(rangeQueryDataStruct)
		if ok {
			c.elemCountLock.Lock()
			c.elementCount -= uint(rq.Len())
			c.elemCountLock.Unlock()
		} else {
			log.Error(fmt.Sprintf("Cache element was not of type rangeQueryDataStruct. Got:%T", v))
		}
	}
	return true
}

type sectionList struct {
	list     *list.List
	listLock sync.RWMutex
}

//Add inserts item into the data structure
func (l *sectionList) Add(item rainslib.Interval) bool {
	l.listLock.Lock()
	defer l.listLock.Unlock()
	for e := l.list.Front(); e != nil; e = e.Next() {
		if e.Value == item {
			return false
		}
	}
	l.list.PushBack(item)
	return true
}

//Delete deletes item from the data structure
func (l *sectionList) Delete(item rainslib.Interval) bool {
	l.listLock.Lock()
	defer l.listLock.Unlock()
	for e := l.list.Front(); e != nil; e = e.Next() {
		if e.Value == item {
			l.list.Remove(e)
			return true
		}
	}
	return false
}

//Get returns true and all intervals which intersect with item if there are any. Otherwise false is returned
func (l *sectionList) Get(item rainslib.Interval) ([]rainslib.Interval, bool) {
	intervals := []rainslib.Interval{}
	l.listLock.RLock()
	defer l.listLock.RUnlock()
	for e := l.list.Front(); e != nil; e = e.Next() {
		val := e.Value.(rainslib.Interval)
		if val.Begin() < item.End() || val.End() > item.Begin() {
			intervals = append(intervals, val)
		}
	}
	return intervals, len(intervals) > 0
}

//returns the number of elements in the data structure
func (l *sectionList) Len() int {
	l.listLock.RLock()
	defer l.listLock.RUnlock()
	return l.list.Len()
}

type elemAndValidity struct {
	elemAndValidTo
	validSince int64
}

type sortedAssertionMetaData struct {
	assertions     []elemAndValidity
	assertionsLock sync.RWMutex
}

//Add adds e to the sorted list at the correct position.
//It returns true if it added e and false if e is already contained
func (s *sortedAssertionMetaData) Add(e elemAndValidity) bool {
	s.assertionsLock.Lock()
	defer s.assertionsLock.Unlock()
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].name >= e.name
	})
	if i == len(s.assertions) {
		s.assertions = append(s.assertions, e)
		return true
	}
	if s.assertions[i] == e {
		return false
	}
	s.assertions = append(s.assertions[:i], append([]elemAndValidity{e}, s.assertions[i:]...)...)
	return true
}

//Delete removes e from the sorted list.
//Returns true if element was successfully deleted from the list. If e not part of list returns false
func (s *sortedAssertionMetaData) Delete(e elemAndValidity) bool {
	s.assertionsLock.Lock()
	defer s.assertionsLock.Unlock()
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].name >= e.name
	})
	if s.assertions[i] != e {
		return false
	}
	s.assertions = append(s.assertions[:i], s.assertions[i+1:]...)
	return true
}

//Len returns the number of element in this sorted slice
func (s *sortedAssertionMetaData) Len() int {
	s.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	return len(s.assertions)
}

//Get returns all assertion meta data which are in the given interval
func (s *sortedAssertionMetaData) Get(interval rainslib.Interval) []elemAndValidity {
	s.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	elements := []elemAndValidity{}
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].name >= interval.Begin()
	})
	if s.assertions[i].name < interval.Begin() {
		return elements
	}
	for ; i < len(s.assertions); i++ {
		if s.assertions[i].name > interval.End() {
			break
		}
		elements = append(elements, s.assertions[i])
	}
	return elements
}

/*
 * assertion cache implementation
 * We have a hierarchical locking system. We first lock the cache to get a pointer to a set data structure. Then we release the lock on the cache and for
 * operations on the set data structure we use a separate lock.
 * We store the elementCount (number of sections in the pendingQueryCacheImpl) separate, as each cache entry can have several querier infos in the set data structure.
 * When we want to update elementCount we must lock using elemCountLock. This lock must never be held when doing a change to the the cache or the set data structure.
 * It can happen that some sections get dropped. This is the case when the cache is full or when we add a section to the set while another go routine deletes the pointer to that
 * set as it was empty before. The second case is expected to occur rarely.
 */
type assertionCacheImpl struct {
	//assertionCache stores to a given <context,zone,name,type> a set of assertions
	assertionCache *cache.Cache
	maxElements    uint
	elementCount   uint
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the set data structure.
	elemCountLock sync.RWMutex

	//rangeMap contains a map from context and zone to a sorted list according to the name of assertions which contains elemAndValidity.
	rangeMap     map[contextAndZone]*sortedAssertionMetaData
	rangeMapLock sync.RWMutex
}

//Add adds an assertion together with a validity to the cache.
//Returns true if cache did not already contain an entry for the given context,zone, name and objType
//If the cache is full it removes an external assertionCacheValue according to some metric.
func (c *assertionCacheImpl) Add(context, zone, name string, objType rainslib.ObjectType, internal bool, value assertionCacheValue) bool {
	set := setDataStruct.New()
	set.Add(value)
	ok := c.assertionCache.Add(set, internal, context, zone, name, objType.String())
	if ok {
		addAssertionToRangeMap(c, context, zone, name, objType, internal, value)
		updateAssertionCacheCount(c)
		handleAssertionCacheSize(c)
		return true
	}
	//there is already a set in the cache, get it and add value.
	v, ok := c.assertionCache.Get(context, zone, name, objType.String())
	if ok {
		set, ok := v.(setContainer)
		if ok {
			ok := set.Add(value)
			if ok {
				addAssertionToRangeMap(c, context, zone, name, objType, internal, value)
				updateAssertionCacheCount(c)
				handleAssertionCacheSize(c)
				log.Debug("Added assertion to cache.", "assertion", *value.section)
				return true
			}
			log.Warn("Set was closed but cache entry was not yet deleted. This case must be rare!")
			return false
		}
		log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
		return false
	}
	//cache entry was deleted in the meantime. Retry
	log.Warn("Cache entry was delete between, trying to add new and getting the existing one. This case must be rare!")
	return c.Add(context, zone, name, objType, internal, value)
}

func addAssertionToRangeMap(c *assertionCacheImpl, context, zone, name string, objType rainslib.ObjectType, internal bool, value assertionCacheValue) {
	c.rangeMapLock.Lock()
	elem := elemAndValidity{
		elemAndValidTo: elemAndValidTo{
			context:    context,
			zone:       zone,
			name:       name,
			objType:    objType,
			validUntil: value.validUntil},
		validSince: value.validSince,
	}
	if val, ok := c.rangeMap[contextAndZone{Context: context, Zone: zone}]; ok {
		c.rangeMapLock.Unlock()
		val.Add(elem)
	} else {
		c.rangeMap[contextAndZone{Context: context, Zone: zone}] = &sortedAssertionMetaData{assertions: []elemAndValidity{elem}}
		c.rangeMapLock.Unlock()
	}
}

//updateAssertionCacheCount increases the element count by one
func updateAssertionCacheCount(c *assertionCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
}

//handleAssertionCacheSize deletes all assertions from the least recently used cache entry if it exceeds the cache size
func handleAssertionCacheSize(c *assertionCacheImpl) {
	c.elemCountLock.RLock()
	if c.elementCount > c.maxElements {
		c.elemCountLock.RUnlock()
		key, _ := c.assertionCache.GetLeastRecentlyUsedKey()
		v, ok := c.assertionCache.Get(key[0], key[1])
		if ok {
			if set, ok := v.(setContainer); ok {
				vals := set.GetAllAndDelete()
				c.assertionCache.Remove(key[0], key[1])
				for _, val := range vals {
					val := val.(assertionCacheValue)
					deleteAssertionFromRangeMap(c, val.section, val.validSince, val.validUntil)
				}
			}
		}
	} else {
		c.elemCountLock.RUnlock()
	}
}

//deleteAssertionFromRangeMap deletes the given assertion from the rangeMap. Return true if it was able to delete the element
func deleteAssertionFromRangeMap(c *assertionCacheImpl, assertion *rainslib.AssertionSection, validSince, validUntil int64) bool {
	c.rangeMapLock.RLock()
	e, ok := c.rangeMap[contextAndZone{Context: assertion.Context, Zone: assertion.SubjectZone}]
	c.rangeMapLock.RUnlock()
	if ok { //if not ok, element was already removed and we are done.
		return e.Delete(elemAndValidity{
			elemAndValidTo: elemAndValidTo{
				context: assertion.Context,
				zone:    assertion.SubjectZone,
				name:    assertion.SubjectName,
				//FIXME CFE when assertion can contain several types. Delete all of them from
				objType:    assertion.Content[0].Type,
				validUntil: validUntil,
			},
			validSince: validSince,
		})
	}
	return false
}

//Get returns true and a set of assertions matching the given key if there exists some. Otherwise false is returned
//If expiredAllowed is false, then no expired assertions will be returned
func (c *assertionCacheImpl) Get(context, zone, name string, objType rainslib.ObjectType, expiredAllowed bool) ([]*rainslib.AssertionSection, bool) {
	assertions := []*rainslib.AssertionSection{}
	v, ok := c.assertionCache.Get(context, zone, name, objType.String())
	if ok {
		if set, ok := v.(setContainer); ok {
			for _, val := range set.GetAll() {
				if value, ok := val.(assertionCacheValue); ok {
					if value.validSince < time.Now().Unix() {
						if expiredAllowed || value.validUntil > time.Now().Unix() {
							assertions = append(assertions, value.section)
						}
					}
				} else {
					log.Error(fmt.Sprintf("Cache element was not of type assertionCacheValue. Got:%T", val))
				}
			}
			return assertions, true
		}
		log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
	}
	return nil, false
}

//GetInRange returns true and a set of valid assertions in the given interval matching the given context and zone if there are any. Otherwise false is returned
func (c *assertionCacheImpl) GetInRange(context, zone string, interval rainslib.Interval) ([]*rainslib.AssertionSection, bool) {
	c.rangeMapLock.RLock()
	sortedList, ok := c.rangeMap[contextAndZone{Context: context, Zone: zone}]
	c.rangeMapLock.RUnlock()
	if ok {
		assertionMetaInfos := sortedList.Get(interval)
		for _, elem := range assertionMetaInfos {
			if elem.validSince < time.Now().Unix() && elem.validUntil > time.Now().Unix() {
				if assertions, ok := c.Get(context, zone, elem.name, elem.objType, false); ok {
					return assertions, true
				}
			}
		}
	}
	return nil, false
}

//Len returns the number of elements in the cache.
func (c *assertionCacheImpl) Len() int {
	c.elemCountLock.RLock()
	defer c.elemCountLock.RUnlock()
	return int(c.elementCount)
}

//RemoveExpiredValues goes through the cache and removes all expired assertions. If for a given context and zone there is no assertion left it removes the entry from cache.
func (c *assertionCacheImpl) RemoveExpiredValues() {
	//Delete expired assertions, shards or zones
	keys := c.assertionCache.Keys()
	for _, key := range keys {
		deleteAssertions(c, false, key[0], key[1])
		updateAssertionCacheStructure(c, key[0], key[1])
	}
	updateAssertionCacheRangeMapping(c)
}

//deleteAssertions removes assertions from the cache and the rangeMap matching the given parameter. It does not update the cache structure.
//if forceDelete is true then all matching assertions are deleted. Otherwise only expired once.
//Returns the number of deleted elements
func deleteAssertions(c *assertionCacheImpl, forceDelete bool, context string, keys ...string) uint {
	deleteCount := uint(0)
	set, ok := getAssertionSet(c, context, keys...)
	if ok {
		vals := set.GetAll()
		//check validity of all container elements and remove expired once or all if forceDelete is set.
		for _, val := range vals {
			v, ok := val.(assertionCacheValue)
			if ok {
				if forceDelete || v.validUntil < time.Now().Unix() {
					ok := set.Delete(val)
					if ok {
						deleteCount++
						ok := deleteAssertionFromRangeMap(c, v.section, v.validSince, v.validUntil)
						if !ok {
							log.Error("Was not able to delete assertion from rangeMap", "assertion", v.section)
						}
					}
				}
			} else {
				log.Error(fmt.Sprintf("set element was not of type assertionCacheValue. Got:%T", val))
			}
		}
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
	return deleteCount
}

//getAssertionSet return true and the set of assertions stored in the cache for the given context and keys=(zone,name,type) if present. Otherwise false is returned
func getAssertionSet(c *assertionCacheImpl, context string, keys ...string) (setContainer, bool) {
	v, ok := c.assertionCache.Get(context, keys...)
	if ok { //check if element is still contained
		set, ok := v.(setContainer)
		if ok {
			return set, true
		}
		log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
	}
	log.Debug("There is no set in the cache for the given context and keys.", "context", context, "keys", keys)
	return nil, false
}

//updateAssertionCacheStructure removes a cache entry if it points to a set without assertions.
func updateAssertionCacheStructure(c *assertionCacheImpl, context, keys string) {
	v, ok := c.assertionCache.Get(context, keys)
	if ok { //check if element is still contained
		set, ok := v.(setContainer)
		if ok { //check that cache element is a setContainer
			if set.Len() == 0 {
				vals := set.GetAllAndDelete()
				if len(vals) == 0 {
					c.assertionCache.Remove(context, keys)
				} else {
					set := setDataStruct.New()
					for _, val := range vals {
						set.Add(val)
					}
					//FIXME CFE here another go routine could come in between. Add an update function to the cache.
					//Right now we overwrite an internal set to an external. This is not the case if we update the value.
					c.assertionCache.Remove(context, keys)
					c.assertionCache.Add(set, false, context, keys)
				}
			}
		} else {
			log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
		}
	}
}

//updateAssertionCacheRangeMapping deletes all entries from the rangeMap which point to an empty slice
func updateAssertionCacheRangeMapping(c *assertionCacheImpl) {
	c.rangeMapLock.Lock()
	defer c.rangeMapLock.Unlock()
	for k, v := range c.rangeMap {
		if v.Len() == 0 {
			delete(c.rangeMap, k)
		}
	}
}

//Remove deletes the given assertion from the cache. Returns true if it was able to remove at least one assertion
func (c *assertionCacheImpl) Remove(assertion *rainslib.AssertionSection) bool {
	//CFE FIXME This does not work if we have several types per assertion
	return deleteAssertions(c, true, assertion.Context, assertion.SubjectZone, assertion.SubjectName, assertion.Content[0].Type.String()) > 0
}

/*
 * active token cache implementation
 */
type activeTokenCacheImpl struct {
	//assertionCache stores to a given <context,zone,name,type> a set of assertions
	activeTokenCache map[rainslib.Token]int64
	maxElements      uint
	elementCount     uint
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the set data structure.
	elemCountLock sync.RWMutex

	//cacheLock is used to protect activeTokenCache from simultaneous access.
	cacheLock sync.RWMutex
}

//isPriority returns true and removes token from the cache if the section containing token has high priority and is not yet expired
func (c *activeTokenCacheImpl) IsPriority(token rainslib.Token) bool {
	c.cacheLock.RLock()
	if exp, ok := c.activeTokenCache[token]; ok {
		c.cacheLock.RUnlock()
		if exp < time.Now().Unix() {
			return false
		}
		c.elemCountLock.Lock()
		c.cacheLock.Lock()
		c.elementCount--
		delete(c.activeTokenCache, token)
		c.cacheLock.Unlock()
		c.elemCountLock.Unlock()
		return true
	}
	c.cacheLock.RUnlock()
	return false
}

//AddToken adds token to the datastructure. The first incoming section with the same token will be processed with high priority
//expiration is the query expiration time which determines how long the token is treated with high priority.
//It returns false if the cache is full and the token is not added to the cache.
func (c *activeTokenCacheImpl) AddToken(token rainslib.Token, expiration int64) bool {
	c.elemCountLock.Lock()
	defer c.elemCountLock.Unlock()
	if c.elementCount < c.maxElements {
		c.cacheLock.Lock()
		defer c.cacheLock.Unlock()
		c.elementCount++
		c.activeTokenCache[token] = expiration
		return true
	}
	return false
}

//DeleteExpiredElements removes all expired tokens from the data structure and logs their information
//Returns all expired tokens
func (c *activeTokenCacheImpl) DeleteExpiredElements() []rainslib.Token {
	tokens := []rainslib.Token{}
	c.elemCountLock.Lock()
	c.cacheLock.Lock()
	defer c.elemCountLock.Unlock()
	defer c.cacheLock.Unlock()
	for token, exp := range c.activeTokenCache {
		if exp < time.Now().Unix() {
			c.elementCount--
			delete(c.activeTokenCache, token)
			tokens = append(tokens, token)
		}
	}
	return tokens
}
