package cache

import (
	"sync"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

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
	section    section.WithSigForward
	expiration int64
}

/*
 * negative assertion cache implementation
 * It keeps track of all assertionCacheValues of a zone in zoneMap (besides the cache)
 * such that we can remove all entries of a zone in case of misbehavior or inconsistencies.
 * It does not support any context
 */
type NegAssertionImpl struct {
	cache   *lruCache.Cache
	counter *safeCounter.Counter
	zoneMap *safeHashMap.Map
}

func NewNegAssertion(maxSize int) *NegAssertionImpl {
	return &NegAssertionImpl{
		cache:   lruCache.New(),
		counter: safeCounter.New(maxSize),
		zoneMap: safeHashMap.New(),
	}
}

//Add adds a shard together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy. It also adds shard to the consistency cache.
func (c *NegAssertionImpl) AddShard(shard *section.Shard, expiration int64, isInternal bool) bool {
	return add(c, shard, expiration, isInternal)
}

//Add adds a pshard together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy. It also adds shard to the consistency cache.
func (c *NegAssertionImpl) AddPshard(pshard *section.Pshard, expiration int64, isInternal bool) bool {
	return add(c, pshard, expiration, isInternal)
}

//Add adds a zone together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy. It also adds zone to the consistency cache.
func (c *NegAssertionImpl) AddZone(zone *section.Zone, expiration int64, isInternal bool) bool {
	return add(c, zone, expiration, isInternal)
}

//add adds a section together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy.
func add(c *NegAssertionImpl, s section.WithSigForward, expiration int64, isInternal bool) bool {
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
		c.counter.Sub(len(v.sections))
		v.mux.Unlock()
	}
	return !isFull
}

//Get returns true and a set of assertions matching the given key if there exist some. Otherwise
//nil and false is returned.
func (c *NegAssertionImpl) Get(zone, context string, interval section.Interval) ([]section.WithSigForward, bool) {
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
	var secs []section.WithSigForward
	for _, sec := range value.sections {
		if section.Intersect(sec.section, interval) {
			secs = append(secs, sec.section)
		}
	}
	return secs, len(secs) > 0
}

//RemoveExpiredValues goes through the cache and removes all expired shards and zones.
func (c *NegAssertionImpl) RemoveExpiredValues() {
	for _, v := range c.cache.GetAll() {
		value := v.(*negAssertionCacheValue)
		deleteCount := 0
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			continue
		}
		for key, va := range value.sections {
			if va.expiration < time.Now().Unix() {
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
func (c *NegAssertionImpl) RemoveZone(zone string) {
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
				c.counter.Sub(len(value.sections))
				value.mux.Unlock()
			}
		}
	}
}

//Checkpoint returns all cached assertions
func (c *NegAssertionImpl) Checkpoint() (sections []section.Section) {
	entries := c.cache.GetAll()
	for _, e := range entries {
		values := e.(*negAssertionCacheValue)
		values.mux.RLock()
		if !values.deleted {
			for _, v := range values.sections {
				sections = append(sections, v.section)
			}
		}
		values.mux.RUnlock()
	}
	return
}

//Len returns the number of elements in the cache.
func (c *NegAssertionImpl) Len() int {
	return c.counter.Value()
}
