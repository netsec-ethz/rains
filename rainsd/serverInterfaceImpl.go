package rainsd

import (
	"bufio"
	"container/list"
	"crypto/rand"
	"fmt"
	"net"
	"rains/rainslib"
	"rains/utils/cache"
	setDataStruct "rains/utils/set"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
)

type newLineFramer struct {
	Scanner   *bufio.Scanner
	firstCall bool
}

func (f newLineFramer) Frame(msg []byte) ([]byte, error) {
	return append(msg, "\n"...), nil
}

func (f *newLineFramer) Deframe() bool {
	if f.firstCall {
		f.Scanner.Split(bufio.ScanLines)
		f.firstCall = false
	}
	return f.Scanner.Scan()
}

func (f newLineFramer) Data() []byte {
	return f.Scanner.Bytes()
}

//PRG pseudo random generator
type PRG struct{}

func (prg PRG) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

/*//TODO CFE replace this with an own implementation
//LRUCache is a concurrency safe cache with a least recently used eviction strategy
type LRUCache struct {
	Cache *lru.Cache
}

//New creates a lru cache with the given parameters
func (c *LRUCache) New(params ...interface{}) error {
	var err error
	c.Cache, err = lru.New(params[0].(int))
	return err
}

//NewWithEvict creates a lru cache with the given parameters and an eviction callback function
func (c *LRUCache) NewWithEvict(onEvicted func(key interface{}, value interface{}), params ...interface{}) error {
	var err error
	c.Cache, err = lru.NewWithEvict(params[0].(int), onEvicted)
	return err
}

//Add adds a value to the cache. If the cache is full the least recently used element will be replaced. Returns true if an eviction occurred.
func (c *LRUCache) Add(key, value interface{}) bool {
	return c.Cache.Add(key, value)
}

//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
func (c *LRUCache) Contains(key interface{}) bool {
	return c.Cache.Contains(key)
}

//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	return c.Cache.Get(key)
}

//Keys returns a slice of the keys in the cache sorted from oldest to newest
func (c *LRUCache) Keys() []interface{} {
	return c.Cache.Keys()
}

//Len returns the number of elements in the cache.
func (c *LRUCache) Len() int {
	return c.Cache.Len()
}

//Remove deletes the given key value pair from the cache
func (c *LRUCache) Remove(key interface{}) {
	c.Cache.Remove(key)
}

//RemoveWithStrategy deletes the least recently used key value pair from the cache
func (c *LRUCache) RemoveWithStrategy() {
	c.Cache.RemoveOldest()
}*/

/*
 *	Connection cache implementation
 */
type connectionCacheImpl struct {
	cache *cache.Cache
}

func (c *connectionCacheImpl) Add(fourTuple string, conn net.Conn) bool {
	return c.cache.Add(conn, false, "", fourTuple)
}

func (c *connectionCacheImpl) Get(fourTuple string) (net.Conn, bool) {
	if v, ok := c.cache.Get("", fourTuple); ok {
		if val, ok := v.(net.Conn); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type net.Conn", "type", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c *connectionCacheImpl) Len() int {
	return c.cache.Len()
}

/*
 *	Capability cache implementation
 */
type capabilityCacheImpl struct {
	connInfoToCap *cache.Cache
	hashToCap     *cache.Cache
}

func (c *capabilityCacheImpl) Add(connInfo ConnInfo, capabilities []rainslib.Capability) bool {
	//FIXME CFE take a SHA-256 hash of the CBOR byte stream derived from normalizing such an array by sorting it in lexicographically increasing order,
	//then serializing it and add it to the cache
	return c.connInfoToCap.Add(capabilities, false, "", connInfo.IPAddrAndPort())
}

func (c *capabilityCacheImpl) Get(connInfo ConnInfo) ([]rainslib.Capability, bool) {
	if v, ok := c.connInfoToCap.Get("", connInfo.IPAddrAndPort()); ok {
		if val, ok := v.([]rainslib.Capability); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type []rainslib.Capability", "type", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c *capabilityCacheImpl) GetFromHash(hash []byte) ([]rainslib.Capability, bool) {
	if v, ok := c.hashToCap.Get("", string(hash)); ok {
		if val, ok := v.([]rainslib.Capability); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type []rainslib.Capability", "type", fmt.Sprintf("%T", v))
	}
	return nil, false
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
	c.cache.Add(list, internal, key.context, key.zone, key.keyAlgo.String())
	v, ok := c.cache.Get(key.context, key.zone, key.keyAlgo.String())
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
	v, ok := c.cache.Get(key.context, key.zone, key.keyAlgo.String())
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
		if key.ValidFrom < time.Now().Unix() && key.ValidUntil > time.Now().Unix() {
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
	maxElements  int
	elementCount int
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the set data structure.
	//TODO CFE take both mutex together, here and cache
	elemCountLock sync.RWMutex
}

//Add adds a section together with a validity to the cache. Returns true if there is not yet a pending query for this context and zone
//If the cache is full it removes all section stored with the least recently used <context, zone> tuple.
func (c *pendingSignatureCacheImpl) Add(context, zone string, value pendingSignatureCacheValue) bool {
	set := setDataStruct.New()
	set.Add(value)
	ok := c.cache.Add(set, false, context, zone)
	if ok {
		updateCount(c) //and book keeping
		return true
	}
	//there is already a set in the cache, get it and add value.
	v, ok := c.cache.Get(context, zone)
	if ok {
		val, ok := v.(setContainer)
		if ok {
			ok := val.Add(value)
			if ok {
				updateCount(c) //and book keeping
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

//updateCount increases the element count by one and if it exceeds the cache size, deletes all sections from the least recently used cache entry.
func updateCount(c *pendingSignatureCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
	if c.elementCount > c.maxElements {
		key, _ := c.cache.GetLeastRecentlyUsedKey()
		c.GetAllAndDelete(key[0], key[1])
	}
}

//GetAllAndDelete returns true and all valid sections associated with the given context and zone if there are any. Otherwise false.
//We simultaneously obtained all elements and close the set data structure. Then we remove the entry from the cache. If in the meantime an Add operation happened,
//then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
func (c *pendingSignatureCacheImpl) GetAllAndDelete(context, zone string) ([]rainslib.MessageSectionWithSig, bool) {
	sections := []rainslib.MessageSectionWithSig{}
	deleteCount := 0
	v, ok := c.cache.Get(context, zone)
	if !ok {
		return sections, false
	}
	if set, ok := v.(setContainer); ok {
		secs := set.GetAllAndDelete()
		deleteCount = len(secs)
		c.cache.Remove(context, zone)
		for _, section := range secs {
			if s, ok := section.(pendingSignatureCacheValue); ok {
				if s.ValidUntil > time.Now().Unix() {
					sections = append(sections, s.section)
				} else {
					log.Info("section expired", "section", s.section, "validity", s.ValidUntil)
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
	deleteCount := 0
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
						if v.ValidUntil < time.Now().Unix() {
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
	return c.elementCount
}

type elemAndValidity struct {
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
	maxElements   int
	elementCount  int
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the set data structure.
	elemCountLock sync.RWMutex

	//activeTokens contains all tokens of sent out queries to be able to find the peers asking for this information.
	activeTokens    map[[16]byte]elemAndValidity
	activeTokenLock sync.RWMutex
}

//Add adds connection information together with a token and a validity to the cache.
//Returns true if cache does not contain a valid entry for context,zone,name,objType else return false
//If the cache is full it removes a pendingQueryCacheValue according to some metric.
func (c *pendingQueryCacheImpl) Add(context, zone, name string, objType rainslib.ObjectType, value pendingQuerySetValue) (bool, rainslib.Token) {
	set := setDataStruct.New()
	set.Add(value)
	token := rainslib.GenerateToken()
	cacheValue := pendingQueryCacheValue{set: set, token: token}
	ok := c.callBackCache.Add(cacheValue, false, context, zone, name, objType.String())
	if ok {
		c.activeTokenLock.Lock()
		c.activeTokens[token] = elemAndValidity{
			context:    context,
			zone:       zone,
			name:       name,
			objType:    objType,
			validUntil: value.ValidUntil,
		}
		c.activeTokenLock.Unlock()
		updatePendingQueryCount(c) //and book keeping
		return true, token
	}
	//there is already a set in the cache, get it and add value.
	v, ok := c.callBackCache.Get(context, zone, name, objType.String())
	if ok {
		val, ok := v.(pendingQueryCacheValue)
		if ok {
			ok := val.set.Add(value)
			if ok {
				updatePendingQueryCount(c) //and book keeping
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

//updateCount increases the element count by one and if it exceeds the cache size, deletes all sections from the least recently used cache entry.
func updatePendingQueryCount(c *pendingQueryCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
	if c.elementCount > c.maxElements {
		key, _ := c.callBackCache.GetLeastRecentlyUsedKey()
		v, ok := c.callBackCache.Get(key[0], key[1])
		if ok {
			if v, ok := v.(pendingQueryCacheValue); ok {
				c.GetAllAndDelete(v.token)
			}
		}
	}
}

//GetAllAndDelete returns true and all valid pendingQueryCacheValues associated with the given token if there are any. Otherwise false
//We remove the entry from the cache and from the activeToken map. Then we simultaneously obtained all elements from the set data structure and close it.
//If in the meantime an Add operation happened, then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
func (c *pendingQueryCacheImpl) GetAllAndDelete(token rainslib.Token) ([]pendingQuerySetValue, bool) {
	sendInfos := []pendingQuerySetValue{}
	deleteCount := 0
	c.activeTokenLock.RLock()
	v, ok := c.activeTokens[token]
	c.activeTokenLock.RUnlock()
	if !ok || v.validUntil < time.Now().Unix() {
		log.Info("Token not anymore in the active Token cache or expired", "token", token, "Now", time.Now().Unix(), "ValidUntil", v.validUntil)
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
		deleteCount = len(queriers)
		for _, querier := range queriers {
			if q, ok := querier.(pendingQuerySetValue); ok {
				if q.ValidUntil > time.Now().Unix() {
					sendInfos = append(sendInfos, q)
				} else {
					log.Info("query expired.", "sender", q.ConnInfo, "token", q.Token)
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
	deleteCount := 0
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
						if v.ValidUntil < time.Now().Unix() {
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
	return c.elementCount
}

/*
 *negative assertion implementation
 * We have a hierarchical locking system. We first lock the cache to get a pointer to a data structure which can efficiently process range queries (e.g. interval tree).
 * Then we release the lock on the cache and for operations on the set data structure we use a separate lock.
 * We store the elementCount (number of sections in the negativeAssertionCacheImpl) separate, as each cache entry can have several sections in the data structure.
 * When we want to update elementCount we must lock using elemCountLock. This lock must never be held when doing a change to the the cache or the underlying data structure.
 * It can happen that some sections get dropped. This is the case when the cache is full or when we add a section to the set while another go routine deletes the pointer to that
 * set as it was empty before. The second case is expected to occur rarely.
 */
type negativeAssertionCacheImpl struct {
	cache        *cache.Cache
	maxElements  int
	elementCount int
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the underlying data structure.
	elemCountLock sync.RWMutex
}

//Add adds a shard or zone together with a validity to the cache.
//Returns true if value was added to the cache.
//If the cache is full it removes an external negativeAssertionCacheValue according to some metric.
func (c *negativeAssertionCacheImpl) Add(context, zone string, internal bool, value negativeAssertionCacheValue) bool {
}

//Get returns true and the shortest sections with the longest validity of a given context and zone containing the name if there exists one. Otherwise false is returned
func (c *negativeAssertionCacheImpl) Get(context, zone, name string) ([]rainslib.MessageSectionWithSig, bool) {
}

//GetAll returns true and all sections of a given context and zone which intersect with the given Range if there is at least one. Otherwise false is returned
//if beginRange and endRange are an empty string then the zone and all shards of that context and zone are returned
func (c *negativeAssertionCacheImpl) GetAll(context, zone, beginRange, endRange string) ([]rainslib.MessageSectionWithSig, bool) {
}

//Len returns the number of elements in the cache.
func (c *negativeAssertionCacheImpl) Len() int {

}

//RemoveExpiredValues goes through the cache and removes all expired values. If for a given context and zone there is no value left it removes the entry from cache.
func (c *negativeAssertionCacheImpl) RemoveExpiredValues() {

}

type sectionList struct {
	list     list.List
	listLock sync.RWMutex
}

//Add inserts item into the data structure
func (l *sectionList) Add(item interval) bool {
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
func (l *sectionList) Delete(item interval) bool {
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

//Get returns all intervals which intersect with item.
func (l *sectionList) Get(item interval) []interval {
	intervals := []interval{}
	l.listLock.RLock()
	defer l.listLock.RUnlock()
	for e := l.list.Front(); e != nil; e = e.Next() {
		if e.Value.(interval).Begin() < item.End() || e.Value.(interval).End() > item.Begin() {
			intervals = append(intervals, e.Value.(interval))
		}
	}
	return intervals
}
