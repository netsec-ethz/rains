package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

//assertionCacheValue is the value stored in the AssertionImpl.cache
type assertionCacheValue struct {
	assertions map[string]assertionExpiration //assertion.Hash -> assertionExpiration
	cacheKey   string
	zone       string
	deleted    bool
	//mux protects deleted and assertions from simultaneous access.
	mux sync.RWMutex
}

type assertionExpiration struct {
	assertion  *section.Assertion
	expiration int64
}

/*
 * assertion cache implementation
 * It keeps track of all assertionCacheValues of a zone in zoneMap (besides the cache)
 * such that we can remove all entries of a zone in case of misbehavior or inconsistencies.
 * It does not support any context
 */
type AssertionImpl struct {
	cache                  *lruCache.Cache
	counter                *safeCounter.Counter
	zoneMap                *safeHashMap.Map
	entriesPerAssertionMap map[string]int //a.Hash() -> int
	mux                    sync.Mutex     //protects entriesPerAssertionMap from simultaneous access
}

func NewAssertion(maxSize int) *AssertionImpl {
	return &AssertionImpl{
		cache:                  lruCache.New(),
		counter:                safeCounter.New(maxSize),
		zoneMap:                safeHashMap.New(),
		entriesPerAssertionMap: make(map[string]int),
	}
}

func mergeSubjectZone(subject, zone string) string {
	if zone == "." {
		return fmt.Sprintf("%s.", subject)
	}
	if subject == "" {
		return zone
	}
	return fmt.Sprintf("%s.%s", subject, zone)
}

//assertionCacheMapKey returns the key for AssertionImpl.cache based on the assertion
func assertionCacheMapKey(name, zone, context string, oType object.Type) string {
	key := fmt.Sprintf("%s %s %d", mergeSubjectZone(name, zone), context, oType)
	log.Debug("assertionCacheMapKey", "key", key)
	return key
}

func assertionCacheMapKeyFQDN(fqdn, context string, oType object.Type) string {
	key := fmt.Sprintf("%s %s %d", fqdn, context, oType)
	log.Debug("assertionCacheMapKeyFQDN", "key", key)
	return key
}

//Add adds an assertion together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy. It also adds the shard to the consistency cache.
func (c *AssertionImpl) Add(a *section.Assertion, expiration int64, isInternal bool) bool {
	isFull := false
	for _, o := range a.Content {
		key := assertionCacheMapKey(a.SubjectName, a.SubjectZone, a.Context, o.Type)
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
			c.mux.Unlock()
		}
		c.counter.Sub(len(v.assertions))
		v.mux.Unlock()
	}
	return !isFull
}

// zoneHierarchy returns a slice of domain names upto the root to try and find a match in the cache.
func zoneHierarchy(fqdn string) []string {
	labels := strings.Split(fqdn, ".")
	if len(labels) == 2 {
		return []string{labels[0] + "."}
	}
	attempts := make([]string, 0)
	for i := 0; i < len(labels)-1; i++ {
		attempts = append(attempts, strings.Join(labels[i:], "."))
	}
	return attempts
}

//Get returns true and a set of assertions matching the given key if there exist some. Otherwise
//nil and false is returned.
// If strict is true then only a direct match for the provided FQDN is looked up.
// Otherwise, a search up the domain name hierarchy is performed to get the topmost match.
func (c *AssertionImpl) Get(fqdn, context string, objType object.Type, strict bool) ([]*section.Assertion, bool) {
	log.Debug("get", "fqdn", fqdn)
	var v interface{}
	var ok bool
	if strict {
		v, ok = c.cache.Get(assertionCacheMapKeyFQDN(fqdn, context, objType))
	} else {
		hierarchy := zoneHierarchy(fqdn)
		log.Debug("hierarchy is", "hierarchy", hierarchy)
		for _, fqdn := range hierarchy {
			log.Debug("trying get with fqdn", "fqdn", fqdn)
			v, ok = c.cache.Get(assertionCacheMapKeyFQDN(fqdn, context, objType))
			if ok {
				break
			}
		}

	}
	if !ok {
		return nil, false
	}
	value := v.(*assertionCacheValue)
	value.mux.RLock()
	defer value.mux.RUnlock()
	if value.deleted {
		return nil, false
	}
	var assertions []*section.Assertion
	for _, av := range value.assertions {
		assertions = append(assertions, av.assertion)
	}
	return assertions, len(assertions) > 0
}

//RemoveExpiredValues goes through the cache and removes all expired assertions from the
//assertionCache and the consistency cache.
func (c *AssertionImpl) RemoveExpiredValues() {
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
func (c *AssertionImpl) RemoveZone(zone string) {
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
					c.mux.Unlock()
				}
				c.counter.Sub(len(value.assertions))
				value.mux.Unlock()
			}
		}
	}
}

//Len returns the number of elements in the cache.
func (c *AssertionImpl) Len() int {
	return c.counter.Value()
}
