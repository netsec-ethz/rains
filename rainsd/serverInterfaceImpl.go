package rainsd

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	setDataStruct "github.com/netsec-ethz/rains/utils/set"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/cache"
	"github.com/netsec-ethz/rains/utils/lruCache"
	"github.com/netsec-ethz/rains/utils/safeCounter"
	"github.com/netsec-ethz/rains/utils/safeHashMap"
)

//connCacheValue is the value pointed to by the hash map in the connectionCacheImpl
type connCacheValue struct {
	connections  *[]net.Conn
	capabilities *[]rainslib.Capability
	//mux is used to protect connections from simultaneous access
	//TODO most access are reads, but do we have a lot of parallel access to the same
	//connCacheValue? If not replace with sync.Mutex.
	mux sync.RWMutex
	//set to true if the pointer to this element is removed from the hash map
	deleted bool
}

/*
 *	Connection cache implementation
 */
type connectionCacheImpl struct {
	cache   *lruCache.Cache
	counter *safeCounter.Counter
}

func getNetworkAndAddr(conn net.Conn) string {
	return fmt.Sprintf("%s %s", conn.RemoteAddr().Network(), conn.RemoteAddr())
}

//AddConnection adds conn to the cache. If the cache is full the least recently used connection is removed.
func (c *connectionCacheImpl) AddConnection(conn net.Conn) {
	v := &connCacheValue{connections: &[]net.Conn{}}
	e, _ := c.cache.GetOrAdd(getNetworkAndAddr(conn), v, false)
	value := e.(*connCacheValue)
	value.mux.Lock()
	*value.connections = append(*value.connections, conn)
	value.mux.Unlock()
	if c.counter.Inc() {
		//cache is full, remove all connections from the least recently used destination
		for {
			if !c.counter.IsFull() {
				break
			}
			key, e := c.cache.GetLeastRecentlyUsed()
			value := e.(*connCacheValue)
			value.mux.Lock()
			if value.deleted {
				value.mux.Unlock()
				continue
			}
			value.deleted = true
			for _, conn := range *value.connections {
				conn.Close()
				c.counter.Dec()
			}
			c.cache.Remove(key)
			value.mux.Unlock()
			break
		}
	}
}

//AddCapability adds capabilities to the destAddr entry. It returns false if there is no entry in
//the cache for dstAddr. If there is already a capability list associated with destAddr, it will be
//overwritten.
func (c *connectionCacheImpl) AddCapabilityList(dstAddr rainslib.ConnInfo, capabilities *[]rainslib.Capability) bool {
	if e, ok := c.cache.Get(dstAddr.NetworkAndAddr()); ok {
		v := e.(*connCacheValue)
		v.mux.Lock()
		defer v.mux.Unlock()
		if v.deleted {
			return false
		}
		v.capabilities = capabilities
		return true
	}
	return false
}

//GetConnection returns true and all cached connection objects to dstAddr.
//GetConnection returns false if there is no cached connection to dstAddr.
func (c *connectionCacheImpl) GetConnection(dstAddr rainslib.ConnInfo) ([]net.Conn, bool) {
	if e, ok := c.cache.Get(dstAddr.NetworkAndAddr()); ok {
		v := e.(*connCacheValue)
		v.mux.RLock()
		defer v.mux.RUnlock()
		if v.deleted {
			return nil, false
		}
		return *v.connections, true
	}
	return nil, false
}

//Get returns true and the capability list of dstAddr.
//Get returns false if there is no capability list of dstAddr.
func (c *connectionCacheImpl) GetCapabilityList(dstAddr rainslib.ConnInfo) ([]rainslib.Capability, bool) {
	if e, ok := c.cache.Get(dstAddr.NetworkAndAddr()); ok {
		v := e.(*connCacheValue)
		v.mux.RLock()
		defer v.mux.RUnlock()
		if v.deleted {
			return nil, false
		}
		return *v.capabilities, true
	}
	return nil, false
}

//Delete closes conn and removes it from the cache
func (c *connectionCacheImpl) CloseAndRemoveConnection(conn net.Conn) {
	conn.Close()
	if e, ok := c.cache.Get(getNetworkAndAddr(conn)); ok {
		v := e.(*connCacheValue)
		v.mux.Lock()
		defer v.mux.Unlock()
		if !v.deleted {
			if len(*v.connections) > 1 {
				for i, connection := range *v.connections {
					//TODO CFE not sure if this comparison works
					if connection == conn {
						*v.connections = append((*v.connections)[:i], (*v.connections)[i+1:]...)
						c.counter.Dec()
					}
				}
			} else {
				v.deleted = true
				c.cache.Remove(getNetworkAndAddr(conn))
				c.counter.Dec()
			}
		}
	}
}

func (c *connectionCacheImpl) Len() int {
	return c.counter.Value()
}

/*
 *	Capability cache implementation
 */
type capabilityCacheImpl struct {
	capabilityMap *lruCache.Cache
	counter       *safeCounter.Counter
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
	_, ok := c.capabilityMap.GetOrAdd(string(hash[:]), &capabilities, false)
	//handle full cache
	if ok && c.counter.Inc() {
		for {
			k, _ := c.capabilityMap.GetLeastRecentlyUsed()
			if _, ok := c.capabilityMap.Remove(k); ok {
				c.counter.Dec()
				break
			}
		}
	}
}

func (c *capabilityCacheImpl) Get(hash []byte) (*[]rainslib.Capability, bool) {
	if v, ok := c.capabilityMap.Get(string(hash)); ok {
		if val, ok := v.(*[]rainslib.Capability); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type *[]rainslib.Capability",
			"actualType", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c *capabilityCacheImpl) Len() int {
	return c.counter.Value()
}

/*
 * Zone key cache implementation
 */
type zoneKeyCacheImpl struct {
	cache   *lruCache.Cache //key=zone,context,algorithmType,phaseID
	counter *safeCounter.Counter
	//warnSize defines the number of public keys after which the add function returns true
	warnSize int
	//maxPublicKeysPerZone defines the number of keys per zone after which a message is logged that
	//this zone uses too many public keys.
	maxPublicKeysPerZone int

	mux sync.Mutex
	//keysPerContextZone counts the number of public keys stored per zone and context
	keysPerContextZone map[string]int //key=zone,context
}

type zoneKeyCacheValue struct {
	//publicKeys is a hash map from publicKey.Hash to the publicKey and the assertion in which the
	//key is contained
	publicKeys    *safeHashMap.Map
	zone          string
	context       string
	algorithmType rainslib.SignatureAlgorithmType
	keyPhase      int

	mux sync.Mutex
	//set to true if the pointer to this element is removed from the hash map
	deleted bool
}

func (v *zoneKeyCacheValue) getCacheKey() string {
	return fmt.Sprintf("%s,%s,%d,%d", v.zone, v.context, v.algorithmType, v.keyPhase)
}

func (v *zoneKeyCacheValue) getContextZone() string {
	return fmt.Sprintf("%s,%s", v.zone, v.context)
}

type publicKeyAssertion struct {
	publicKey rainslib.PublicKey
	assertion *rainslib.AssertionSection
}

//Add adds publicKey together with the assertion containing it to the cache. Returns false if
//the cache exceeds a configured (during initialization of the cache) amount of entries. If the
//cache is full it removes a public key according to some metric. The cache logs a message when
//a zone has more than a certain (configurable) amount of public keys. (An external service can
//then decide if it wants to blacklist a given zone). If the internal flag is set, the publicKey
//will only be removed after it expired.
func (c *zoneKeyCacheImpl) Add(assertion *rainslib.AssertionSection, publicKey rainslib.PublicKey, internal bool) bool {
	subjectName := assertion.SubjectName
	if assertion.SubjectName == "@" {
		subjectName = assertion.SubjectZone
	}
	cacheValue := &zoneKeyCacheValue{publicKeys: safeHashMap.New(), zone: subjectName,
		context: assertion.Context, algorithmType: publicKey.Algorithm, keyPhase: publicKey.KeyPhase}
	e, _ := c.cache.GetOrAdd(cacheValue.getCacheKey(), cacheValue, internal)
	v := e.(*zoneKeyCacheValue)
	v.mux.Lock() //This lock assures that the lru removal of another add method or the reap
	//function do not remove a pointer to this zoneKeyCacheValue.
	if v.deleted {
		v.mux.Unlock()
		return c.Add(assertion, publicKey, internal)
	}
	_, ok := v.publicKeys.GetOrAdd(publicKey.Hash(),
		publicKeyAssertion{publicKey: publicKey, assertion: assertion})
	if ok {
		c.mux.Lock()
		c.keysPerContextZone[v.getContextZone()]++
		if c.keysPerContextZone[v.getContextZone()] > c.maxPublicKeysPerZone {
			log.Warn("There are too many publicKeys for a zone and context", "zone", subjectName,
				"context", assertion.Context, "allowed", c.maxPublicKeysPerZone, "actual",
				c.keysPerContextZone[v.getContextZone()])
		}
		c.mux.Unlock()
		v.mux.Unlock()
		if c.counter.Inc() {
			//cache is full, remove least recently used public key.
			for {
				if !c.counter.IsFull() {
					return false
				}
				_, e := c.cache.GetLeastRecentlyUsed()
				val := e.(*zoneKeyCacheValue)
				val.mux.Lock() //This lock makes sure that no other add method can insert a new
				//entry to this zoneKeyCacheValue publicKeys. Thus, it is safe to first get all keys
				//and then remove one after an other from publicKeys.
				if val.deleted {
					val.mux.Unlock()
					continue
				}
				val.deleted = true
				for _, key := range val.publicKeys.GetAllKeys() {
					if _, ok := val.publicKeys.Remove(key); ok {
						c.counter.Dec()
						c.mux.Lock()
						c.keysPerContextZone[val.getContextZone()]--
						c.mux.Unlock()
					}
				}
				c.cache.Remove(val.getCacheKey())
				val.mux.Unlock()
				return false
			}
		}
	}
	return c.counter.Value() < c.warnSize
}

//Get returns true and a valid public key matching zone and publicKeyID. It returns false if
//there exists no valid public key in the cache.
func (c *zoneKeyCacheImpl) Get(zone, context string, sigMetaData rainslib.SignatureMetaData) (
	rainslib.PublicKey, *rainslib.AssertionSection, bool) {
	e, ok := c.cache.Get(fmt.Sprintf("%s,%s,%d,%d", zone, context, sigMetaData.Algorithm, sigMetaData.KeyPhase))
	if !ok {
		return rainslib.PublicKey{}, nil, false
	}
	values := e.(*zoneKeyCacheValue).publicKeys.GetAll()
	for _, v := range values {
		key := v.(publicKeyAssertion).publicKey
		if key.ValidUntil > time.Now().Unix() {
			//key is non expired and valid
			if key.ValidSince <= sigMetaData.ValidUntil && key.ValidUntil >= sigMetaData.ValidSince {
				return key, v.(publicKeyAssertion).assertion, true
			}
		}
	}
	return rainslib.PublicKey{}, nil, false
}

//RemoveExpiredKeys deletes all expired public keys from the cache.
func (c *zoneKeyCacheImpl) RemoveExpiredKeys() {
	values := c.cache.GetAll()
	for _, value := range values {
		val := value.(*zoneKeyCacheValue)
		keys := val.publicKeys.GetAllKeys()
		for _, key := range keys {
			if k, ok := val.publicKeys.Get(key); ok && k.(publicKeyAssertion).publicKey.ValidUntil < time.Now().Unix() {
				if _, ok := val.publicKeys.Remove(key); ok {
					c.counter.Dec()
					c.mux.Lock()
					c.keysPerContextZone[val.getContextZone()]--
					c.mux.Unlock()
				}
			}
		}
		val.mux.Lock() //This lock makes sure that no add methods are interfering while deleting
		//the pointer to this entry.
		if !val.deleted && val.publicKeys.Len() == 0 {
			val.deleted = true
			c.cache.Remove(val.getCacheKey())
		}
		val.mux.Unlock()
	}
}

//Len returns the number of public keys currently in the cache.
func (c *zoneKeyCacheImpl) Len() int {
	return c.counter.Value()
}

//pendingSignatureCacheValue is the value received from the pendingQuery cache
type pendingSignatureCacheValue struct {
	sectionWSSender sectionWithSigSender
	validUntil      int64
}

func (p pendingSignatureCacheValue) Hash() string {
	return fmt.Sprintf("%s_%d", p.sectionWSSender.Hash(), p.validUntil)
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

//pendingSignatureCacheValue is the value received from the pendingQuery cache
type pendingQuerySetValue struct {
	connInfo   rainslib.ConnInfo
	token      rainslib.Token //Token from the received query
	validUntil int64
}

func (p pendingQuerySetValue) Hash() string {
	return fmt.Sprintf("%s_%v_%d", p.connInfo.Hash(), p.token, p.validUntil)
}

//pendingSignatureCacheValue is the value received from the pendingQuery cache
type pendingQueryCacheValue struct {
	set   setContainer
	token rainslib.Token //Token of this servers query
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

//assertionCacheValue is the value stored in the assertionCacheImpl.cache
type assertionCacheValue struct {
	assertions map[string]assertionExpiration //assertion.Hash -> assertionExpiration
	cacheKey   string
	zone       string
	deleted    bool
	//mux protects deleted and assertions from simultaneous access.
	mux sync.RWMutex
}

type assertionExpiration struct {
	assertion  *rainslib.AssertionSection
	expiration int64
}

/*
 * assertion cache implementation
 * It keeps track of all assertionCacheValues of a zone in zoneMap (besides the cache)
 * such that we can remove all entries of a zone in case of misbehavior or inconsistencies.
 * It does not support any context
 */
type assertionCacheImpl struct {
	cache                  *lruCache.Cache
	counter                *safeCounter.Counter
	zoneMap                *safeHashMap.Map
	entriesPerAssertionMap map[string]int //a.Hash() -> int
	mux                    sync.Mutex     //protects entriesPerAssertionMap from simultaneous access
}

//Add adds an assertion together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy. It also adds the shard to the consistency cache.
func (c *assertionCacheImpl) Add(a *rainslib.AssertionSection, expiration int64, isInternal bool) bool {
	isFull := false
	consistCache.Add(a)
	for _, o := range a.Content {
		key := fmt.Sprintf("%s %s %s %d", a.SubjectName, a.SubjectZone, a.Context, o.Type)
		cacheValue := assertionCacheValue{
			assertions: make(map[string]assertionExpiration),
			cacheKey:   key,
			zone:       a.SubjectZone,
		}
		v, new := c.cache.GetOrAdd(key, &cacheValue, isInternal)
		value := v.(*assertionCacheValue)
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			return c.Add(a, expiration, isInternal)
		}
		if new {
			val, _ := c.zoneMap.GetOrAdd(a.SubjectZone, safeHashMap.New())
			val.(*safeHashMap.Map).Add(key, true)
		}
		if _, ok := value.assertions[a.Hash()]; !ok {
			value.assertions[a.Hash()] = assertionExpiration{assertion: a, expiration: expiration}
			c.mux.Lock()
			c.entriesPerAssertionMap[a.Hash()]++
			c.mux.Unlock()
			isFull = c.counter.Inc()
		}
		value.mux.Unlock()
	}
	//Remove a from consistency cache if it was not added to assertion cache.
	c.mux.Lock()
	if c.entriesPerAssertionMap[a.Hash()] == 0 {
		consistCache.Remove(a)
	}
	c.mux.Unlock()
	//Remove elements according to lru strategy
	for c.counter.IsFull() {
		key, value := c.cache.GetLeastRecentlyUsed()
		if value == nil {
			break
		}
		v := value.(*assertionCacheValue)
		v.mux.Lock()
		if v.deleted {
			v.mux.Unlock()
			continue
		}
		v.deleted = true
		c.cache.Remove(key)
		if val, ok := c.zoneMap.Get(v.zone); ok {
			val.(*safeHashMap.Map).Remove(v.cacheKey)
		}
		for _, val := range v.assertions {
			c.mux.Lock()
			c.entriesPerAssertionMap[val.assertion.Hash()]--
			if c.entriesPerAssertionMap[val.assertion.Hash()] == 0 {
				delete(c.entriesPerAssertionMap, val.assertion.Hash())
				consistCache.Remove(val.assertion)
			}
			c.mux.Unlock()
		}
		c.counter.Sub(len(v.assertions))
		v.mux.Unlock()
	}
	return !isFull
}

//Get returns true and a set of assertions matching the given key if there exist some. Otherwise
//nil and false is returned.
func (c *assertionCacheImpl) Get(name, zone, context string, objType rainslib.ObjectType) ([]*rainslib.AssertionSection, bool) {
	key := fmt.Sprintf("%s %s %s %d", name, zone, context, objType)
	v, ok := c.cache.Get(key)
	if !ok {
		return nil, false
	}
	value := v.(*assertionCacheValue)
	value.mux.RLock()
	defer value.mux.RUnlock()
	if value.deleted {
		return nil, false
	}
	var assertions []*rainslib.AssertionSection
	for _, av := range value.assertions {
		assertions = append(assertions, av.assertion)
	}
	return assertions, len(assertions) > 0
}

//RemoveExpiredValues goes through the cache and removes all expired assertions from the
//assertionCache and the consistency cache.
func (c *assertionCacheImpl) RemoveExpiredValues() {
	for _, v := range c.cache.GetAll() {
		value := v.(*assertionCacheValue)
		deleteCount := 0
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			continue
		}
		for key, va := range value.assertions {
			if va.expiration < time.Now().Unix() {
				c.mux.Lock()
				c.entriesPerAssertionMap[va.assertion.Hash()]--
				if c.entriesPerAssertionMap[va.assertion.Hash()] == 0 {
					delete(c.entriesPerAssertionMap, va.assertion.Hash())
					consistCache.Remove(va.assertion)
				}
				c.mux.Unlock()
				delete(value.assertions, key)
				deleteCount++
			}
		}
		if len(value.assertions) == 0 {
			value.deleted = true
			c.cache.Remove(value.cacheKey)
			if set, ok := c.zoneMap.Get(value.zone); ok {
				set.(*safeHashMap.Map).Remove(value.cacheKey)
			}
		}
		value.mux.Unlock()
		c.counter.Sub(deleteCount)
	}
}

//RemoveZone deletes all assertions in the assertionCache and consistencyCache of the given zone.
func (c *assertionCacheImpl) RemoveZone(zone string) {
	if set, ok := c.zoneMap.Remove(zone); ok {
		for _, key := range set.(*safeHashMap.Map).GetAllKeys() {
			v, ok := c.cache.Remove(key)
			if ok {
				value := v.(*assertionCacheValue)
				value.mux.Lock()
				if value.deleted {
					value.mux.Unlock()
					continue
				}
				value.deleted = true
				for _, val := range value.assertions {
					c.mux.Lock()
					c.entriesPerAssertionMap[val.assertion.Hash()]--
					if c.entriesPerAssertionMap[val.assertion.Hash()] == 0 {
						delete(c.entriesPerAssertionMap, val.assertion.Hash())
						consistCache.Remove(val.assertion)
					}
					c.mux.Unlock()
				}
				c.counter.Sub(len(value.assertions))
				value.mux.Unlock()
			}
		}
	}
}

//Len returns the number of elements in the cache.
func (c *assertionCacheImpl) Len() int {
	return c.counter.Value()
}

//negAssertionCacheValue is the value stored in the assertionCacheImpl.cache
type negAssertionCacheValue struct {
	sections map[string]sectionExpiration //section.Hash -> sectionExpiration
	cacheKey string
	zone     string
	deleted  bool
	//mux protects deleted and assertions from simultaneous access.
	mux sync.RWMutex
}

type sectionExpiration struct {
	section    rainslib.MessageSectionWithSigForward
	expiration int64
}

/*
 * negative assertion cache implementation
 * It keeps track of all assertionCacheValues of a zone in zoneMap (besides the cache)
 * such that we can remove all entries of a zone in case of misbehavior or inconsistencies.
 * It does not support any context
 */
type negativeAssertionCacheImpl struct {
	cache   *lruCache.Cache
	counter *safeCounter.Counter
	zoneMap *safeHashMap.Map
}

//Add adds a shard together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy. It also adds shard to the consistency cache.
func (c *negativeAssertionCacheImpl) AddShard(shard *rainslib.ShardSection, expiration int64, isInternal bool) bool {
	return add(c, shard, expiration, isInternal)
}

//Add adds a zone together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy. It also adds zone to the consistency cache.
func (c *negativeAssertionCacheImpl) AddZone(zone *rainslib.ZoneSection, expiration int64, isInternal bool) bool {
	return add(c, zone, expiration, isInternal)
}

//add adds a section together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy.
func add(c *negativeAssertionCacheImpl, s rainslib.MessageSectionWithSigForward, expiration int64, isInternal bool) bool {
	isFull := false
	key := fmt.Sprintf("%s %s", s.GetSubjectZone(), s.GetContext())
	cacheValue := negAssertionCacheValue{
		sections: make(map[string]sectionExpiration),
		cacheKey: key,
		zone:     s.GetSubjectZone(),
	}
	v, new := c.cache.GetOrAdd(key, &cacheValue, isInternal)
	value := v.(*negAssertionCacheValue)
	value.mux.Lock()
	if value.deleted {
		value.mux.Unlock()
		return add(c, s, expiration, isInternal)
	}
	if new {
		val, _ := c.zoneMap.GetOrAdd(s.GetSubjectZone(), safeHashMap.New())
		val.(*safeHashMap.Map).Add(key, true)
	}
	if _, ok := value.sections[s.Hash()]; !ok {
		consistCache.Add(s)
		value.sections[s.Hash()] = sectionExpiration{section: s, expiration: expiration}
		isFull = c.counter.Inc()
	}
	value.mux.Unlock()
	//Remove elements according to lru strategy
	for c.counter.IsFull() {
		key, value := c.cache.GetLeastRecentlyUsed()
		if value == nil {
			break
		}
		v := value.(*negAssertionCacheValue)
		v.mux.Lock()
		if v.deleted {
			v.mux.Unlock()
			continue
		}
		v.deleted = true
		c.cache.Remove(key)
		if val, ok := c.zoneMap.Get(v.zone); ok {
			val.(*safeHashMap.Map).Remove(v.cacheKey)
		}
		for _, val := range v.sections {
			consistCache.Remove(val.section)
		}
		c.counter.Sub(len(v.sections))
		v.mux.Unlock()
	}
	return !isFull
}

//Get returns true and a set of assertions matching the given key if there exist some. Otherwise
//nil and false is returned.
func (c *negativeAssertionCacheImpl) Get(zone, context string, interval rainslib.Interval) ([]rainslib.MessageSectionWithSigForward, bool) {
	key := fmt.Sprintf("%s %s", zone, context)
	v, ok := c.cache.Get(key)
	if !ok {
		return nil, false
	}
	value := v.(*negAssertionCacheValue)
	value.mux.RLock()
	defer value.mux.RUnlock()
	if value.deleted {
		return nil, false
	}
	var sections []rainslib.MessageSectionWithSigForward
	for _, sec := range value.sections {
		if rainslib.Intersect(sec.section, interval) {
			sections = append(sections, sec.section)
		}
	}
	return sections, len(sections) > 0
}

//RemoveExpiredValues goes through the cache and removes all expired shards and zones from the
//assertionCache and the consistency cache.
func (c *negativeAssertionCacheImpl) RemoveExpiredValues() {
	for _, v := range c.cache.GetAll() {
		value := v.(*negAssertionCacheValue)
		deleteCount := 0
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			continue
		}
		for key, sec := range value.sections {
			if sec.expiration < time.Now().Unix() {
				consistCache.Remove(sec.section)
				delete(value.sections, key)
				deleteCount++
			}
		}
		if len(value.sections) == 0 {
			value.deleted = true
			c.cache.Remove(value.cacheKey)
			if set, ok := c.zoneMap.Get(value.zone); ok {
				set.(*safeHashMap.Map).Remove(value.cacheKey)
			}
		}
		value.mux.Unlock()
		c.counter.Sub(deleteCount)
	}
}

//RemoveZone deletes all shards and zones in the assertionCache and consistencyCache of the given
//subjectZone.
func (c *negativeAssertionCacheImpl) RemoveZone(zone string) {
	if set, ok := c.zoneMap.Remove(zone); ok {
		for _, key := range set.(*safeHashMap.Map).GetAllKeys() {
			v, ok := c.cache.Remove(key)
			if ok {
				value := v.(*negAssertionCacheValue)
				value.mux.Lock()
				if value.deleted {
					value.mux.Unlock()
					continue
				}
				value.deleted = true
				for _, val := range value.sections {
					consistCache.Remove(val.section)
				}
				c.counter.Sub(len(value.sections))
				value.mux.Unlock()
			}
		}
	}
}

//Len returns the number of elements in the cache.
func (c *negativeAssertionCacheImpl) Len() int {
	return c.counter.Value()
}

type consistencyCacheValue struct {
	sections map[string]rainslib.MessageSectionWithSigForward
	mux      sync.RWMutex
	deleted  bool
}

/*
 * consistency cache implementation
 * TODO CFE use interval trees to efficiently find overlapping intervals
 */
type consistencyCacheImpl struct {
	ctxZoneMap map[string]*consistencyCacheValue
	mux        sync.RWMutex
}

//Add adds section to the consistency cache.
func (c *consistencyCacheImpl) Add(section rainslib.MessageSectionWithSigForward) {
	ctxZoneMapKey := fmt.Sprintf("%s %s", section.GetSubjectZone(), section.GetContext())
	c.mux.Lock()
	v, ok := c.ctxZoneMap[ctxZoneMapKey]
	if !ok {
		v = &consistencyCacheValue{sections: make(map[string]rainslib.MessageSectionWithSigForward)}
		c.ctxZoneMap[ctxZoneMapKey] = v
	}
	c.mux.Unlock()
	v.mux.Lock()
	if v.deleted {
		v.mux.Unlock()
		c.Add(section)
	}
	v.sections[section.Hash()] = section
	v.mux.Unlock()
}

//Get returns all sections from the cache with the given zone and context that are overlapping
//with interval.
func (c *consistencyCacheImpl) Get(subjectZone, context string, interval rainslib.Interval) []rainslib.MessageSectionWithSigForward {
	ctxZoneMapKey := fmt.Sprintf("%s %s", subjectZone, context)
	c.mux.RLock()
	v, ok := c.ctxZoneMap[ctxZoneMapKey]
	if !ok {
		c.mux.RUnlock()
		return nil
	}
	c.mux.RUnlock()
	v.mux.RLock()
	defer v.mux.RUnlock()
	if v.deleted {
		return nil
	}
	var sections []rainslib.MessageSectionWithSigForward
	for _, section := range v.sections {
		if rainslib.Intersect(section, interval) {
			sections = append(sections, section)
		}
	}
	return sections
}

//Remove deletes section from the consistency cache
func (c *consistencyCacheImpl) Remove(section rainslib.MessageSectionWithSigForward) {
	ctxZoneMapKey := fmt.Sprintf("%s %s", section.GetSubjectZone(), section.GetContext())
	c.mux.Lock()
	if v, ok := c.ctxZoneMap[ctxZoneMapKey]; ok {
		c.mux.Unlock()
		v.mux.Lock()
		if v.deleted {
			v.mux.Unlock()
			log.Error("Value already removed or not yet stored [consistencyCacheValue]. This case should never happen.", "section", section)
			//See long comment below
			return
		}
		delete(v.sections, section.Hash())
		if len(v.sections) == 0 {
			v.deleted = true
			c.mux.Lock()
			delete(c.ctxZoneMap, ctxZoneMapKey)
			c.mux.Unlock()
		}
		v.mux.Unlock()
	} else {
		c.mux.Unlock()
		log.Error("Value already removed or not yet stored [ctxZoneMap]. This case should never happen.", "section", section)
		//This case could happen if the assertion cache would create go routines (for efficiency
		//reasons) to add and remove entries of the consistency cache. When two go routines are
		//almost simultaneously created, the first to add and the second to remove the same entry,
		//and the remove go routine is faster in obtaining the lock we are in this case and will
		//never remove the later added value from the consistency cache. Such a scenario can likely
		//occur in the event of a DOS attack and mitigation. Thus, we either wait in the other cache
		//until the operation on this cache is done or the remove function spins on this value with
		//exponential backoff.
	}
}

/*
 * active token cache implementation
 */
type activeTokenCacheImpl struct {
	//activeTokenCache maps tokens to their expiration time
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
