package rainsd

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
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

type pendingKeyCacheValue struct {
	mux sync.Mutex
	//sections is a hash map from algoType and phase to a hash map keyed by section.Hash and
	//pointing to sectionWithSigSender in which section is contained
	sections map[string]map[string]sectionWithSigSender
	//zoneCtx is zoneCtxMap's key
	zoneCtx string
	//token is tokenMap's key
	token rainslib.Token
	//sendTo is the connection information of the server to which the delegation query has been sent
	sendTo rainslib.ConnInfo
	//expiration is the time when the delegation query expires in unix time
	expiration int64
	//set to true if the pointer to this element is removed from both hash maps
	deleted bool
}

func zoneCtxKey(zone, context string) string {
	return fmt.Sprintf("%s %s", zone, context)
}

func algoPhaseKey(algoType rainslib.SignatureAlgorithmType, phase int) string {
	return fmt.Sprintf("%s %d", algoType, phase)
}

type pendingKeyCacheImpl struct {
	//zoneCtxMap is a map from zoneContext to *pendingKeyCacheValue safe for concurrent use
	zoneCtxMap *safeHashMap.Map
	//tokenMap is a map from token to *pendingKeyCacheValue safe for concurrent use
	tokenMap *safeHashMap.Map

	counter *safeCounter.Counter
}

//Add adds sectionSender to the cache and returns true if a new delegation should be sent.
func (c *pendingKeyCacheImpl) Add(sectionSender sectionWithSigSender,
	algoType rainslib.SignatureAlgorithmType, phase int) bool {
	if c.counter.Inc() {
		log.Warn("pending key cache is full", "size", c.counter.Value())
		c.counter.Dec()
		return false
	}
	section := sectionSender.Section
	entry := &pendingKeyCacheValue{
		zoneCtx:    zoneCtxKey(section.GetSubjectZone(), section.GetContext()),
		sections:   make(map[string]map[string]sectionWithSigSender),
		expiration: time.Now().Add(time.Second).Unix(),
	}
	newSet := make(map[string]sectionWithSigSender)
	newSet[section.Hash()] = sectionSender
	entry.sections[algoPhaseKey(algoType, phase)] = newSet
	if entry, ok := c.zoneCtxMap.GetOrAdd(entry.zoneCtx, entry); !ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			return c.Add(sectionSender, algoType, phase)
		}
		defer value.mux.Unlock()
		if set, ok := value.sections[algoPhaseKey(algoType, phase)]; !ok {
			value.sections[algoPhaseKey(algoType, phase)] = newSet
		} else {
			if _, ok := set[section.Hash()]; !ok {
				set[section.Hash()] = sectionSender
			} else {
				c.counter.Dec()
			}
		}
		isExpired := value.expiration < time.Now().Unix()
		if isExpired {
			value.expiration = time.Now().Add(time.Second).Unix()
			log.Warn("pending key cache entry has expired", "value", value)
		}
		return isExpired
	}
	return true
}

//AddToken adds token to the token map where the value of the map corresponds to the cache entry
//matching the given zone and context. Token is only added to the map if a matching cache entry
//exists without a token. False is returned if no matching cache entry exists or it already contains
//a token
func (c *pendingKeyCacheImpl) AddToken(token rainslib.Token, expiration int64,
	sendTo rainslib.ConnInfo, zone, context string) bool {
	if entry, ok := c.zoneCtxMap.Get(zoneCtxKey(zone, context)); ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		defer value.mux.Unlock()
		if value.token == [16]byte{} {
			value.token = token
			value.expiration = expiration
			value.sendTo = sendTo
			_, ok := c.tokenMap.GetOrAdd(token.String(), value)
			if !ok {
				log.Error("token already in cache. Token was reused too early", "token", token)
			}
			return ok
		}
	}
	return false
}

//GetAndRemove returns all sections who contain a signature matching the given parameter and
//deletes them from the cache. It returns true if at least one section is returned. The token
//map is updated if necessary.
func (c *pendingKeyCacheImpl) GetAndRemove(zone, context string, algoType rainslib.SignatureAlgorithmType, phase int) ([]sectionWithSigSender, bool) {
	if entry, ok := c.zoneCtxMap.Get(zoneCtxKey(zone, context)); ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		defer value.mux.Unlock()
		if value.deleted {
			return nil, false
		}
		if set, ok := value.sections[algoPhaseKey(algoType, phase)]; ok {
			if len(value.sections) == 1 {
				value.deleted = true
				e, _ := c.zoneCtxMap.Remove(zoneCtxKey(zone, context))
				c.tokenMap.Remove(e.(*pendingKeyCacheValue).token.String())
			}
			sectionSenders := []sectionWithSigSender{}
			for _, v := range set {
				sectionSenders = append(sectionSenders, v)
			}
			delete(value.sections, algoPhaseKey(algoType, phase))
			c.counter.Sub(len(sectionSenders))
			return sectionSenders, len(sectionSenders) > 0
		}
	}
	return nil, false
}

//GetAndRemoveByToken returns all sections who correspond to token and deletes them from the
//cache. It returns true if at least one section is returned. Token is removed from the token
//map.
func (c *pendingKeyCacheImpl) GetAndRemoveByToken(token rainslib.Token) ([]sectionWithSigSender, bool) {
	if entry, ok := c.tokenMap.Remove(token.String()); ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			return nil, false
		}
		value.deleted = true
		c.zoneCtxMap.Remove(value.zoneCtx)
		value.mux.Unlock()
		sectionSenders := []sectionWithSigSender{}
		for _, set := range value.sections {
			for _, sectionSender := range set {
				sectionSenders = append(sectionSenders, sectionSender)
			}
		}
		c.counter.Sub(len(sectionSenders))
		return sectionSenders, len(sectionSenders) > 0
	}
	return nil, false
}

//ContainsToken returns true if token is in the token map.
func (c *pendingKeyCacheImpl) ContainsToken(token rainslib.Token) bool {
	_, ok := c.tokenMap.Get(token.String())
	return ok
}

//RemoveExpiredValues deletes all sections of an expired entry and updates the token map if
//necessary. It logs which sections are removed and to which server the query has been sent.
func (c *pendingKeyCacheImpl) RemoveExpiredValues() {
	for _, value := range c.zoneCtxMap.GetAll() {
		v := value.(*pendingKeyCacheValue)
		v.mux.Lock()
		if v.deleted {
			v.mux.Unlock()
			continue
		}
		if v.expiration < time.Now().Unix() {
			v.deleted = true
			c.tokenMap.Remove(v.token.String())
			c.zoneCtxMap.Remove(v.zoneCtx)
			log.Warn("pending key cache entry has expired", "value", v)
			for _, set := range v.sections {
				for k := range set {
					log.Warn("", "", k)
				}
				c.counter.Sub(len(set))
			}
		}
		v.mux.Unlock()
	}
}

//Len returns the number of sections in the cache
func (c *pendingKeyCacheImpl) Len() int {
	return c.counter.Value()
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
	key := zoneCtxKey(s.GetSubjectZone(), s.GetContext())
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
	key := zoneCtxKey(zone, context)
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
