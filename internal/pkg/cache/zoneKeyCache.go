package cache

import (
	"fmt"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

type zoneKeyCacheValue struct {
	//publicKeys is a hash map from publicKey.Hash to the publicKey and the assertion in which the
	//key is contained
	publicKeys    *safeHashMap.Map
	zone          string
	context       string
	algorithmType algorithmTypes.Signature
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
	publicKey keys.PublicKey
	assertion *section.Assertion
}

/*
 * Zone key cache implementation
 */
type ZoneKeyImpl struct {
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

func NewZoneKey(maxSize, warnSize, maxKeysPerZone int) *ZoneKeyImpl {
	return &ZoneKeyImpl{
		cache:                lruCache.New(),
		counter:              safeCounter.New(maxSize),
		warnSize:             warnSize,
		maxPublicKeysPerZone: maxKeysPerZone,
		keysPerContextZone:   make(map[string]int),
	}
}

// Add adds publicKey together with the assertion containing it to the cache. Returns false if
// the cache exceeds a configured (during initialization of the cache) amount of entries. If the
// cache is full it removes a public key according to some metric. The cache logs a message when
// a zone has more than a certain (configurable) amount of public keys. (An external service can
// then decide if it wants to blacklist a given zone). If the internal flag is set, the publicKey
// will only be removed after it expired.
func (c *ZoneKeyImpl) Add(assertion *section.Assertion, publicKey keys.PublicKey, internal bool) bool {
	log.Info("Adding key to cache", "publicKey", publicKey, "assertion", assertion)
	subjectName := assertion.FQDN()
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

// Get returns true and a valid public key matching zone and publicKeyID. It returns false if
// there exists no valid public key in the cache.
func (c *ZoneKeyImpl) Get(zone, context string, sigMetaData signature.MetaData) (
	keys.PublicKey, *section.Assertion, bool) {
	e, ok := c.cache.Get(fmt.Sprintf("%s,%s,%d,%d", zone, context, sigMetaData.Algorithm, sigMetaData.KeyPhase))
	if !ok {
		return keys.PublicKey{}, nil, false
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
	return keys.PublicKey{}, nil, false
}

// RemoveExpiredKeys deletes all expired public keys from the cache.
func (c *ZoneKeyImpl) RemoveExpiredKeys() {
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

// Checkpoint returns all cached assertions
func (c *ZoneKeyImpl) Checkpoint() (assertions []section.Section) {
	entries := c.cache.GetAll()
	for _, e := range entries {
		values := e.(*zoneKeyCacheValue).publicKeys.GetAll()
		for _, v := range values {
			assertions = append(assertions, v.(publicKeyAssertion).assertion)
		}
	}
	return
}

// Len returns the number of public keys currently in the cache.
func (c *ZoneKeyImpl) Len() int {
	return c.counter.Value()
}

func zoneCtxKey(zone, context string) string {
	return fmt.Sprintf("%s %s", zone, context)
}
