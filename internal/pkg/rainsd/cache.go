package rainsd

import (
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/message"
)

type Caches struct {
	//connCache stores connections of this server. It is not guaranteed that a returned connection is still active.
	ConnCache connectionCache

	//capabilities stores known hashes of capabilities and for each connInfo what capability the communication partner has.
	Capabilities capabilityCache

	//zoneKeyCache is used to store public keys of zones and a pointer to assertions containing them.
	ZoneKeyCache zonePublicKeyCache

	//revZoneKeyCache is used to store public keys of addressZones and a pointer to delegation
	//assertions containing them.
	//TODO CFE implement it
	RevZoneKeyCache revZonePublicKeyCache

	//pendingSignatures contains all sections that are waiting for a delegation query to arrive such that their signatures can be verified.
	PendingKeys pendingKeyCache

	//pendingQueries contains a mapping from all self issued pending queries to the set of message bodies waiting for it.
	PendingQueries pendingQueryCache

	//assertionCache contains a set of valid assertions where some of them might be expired.
	//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
	AssertionsCache assertionCache

	//negAssertionCache contains for each zone and context an interval tree to find all shards and zones containing a specific assertion
	//for a zone the range is infinit: range "",""
	//for a shard the range is given as declared in the section.
	//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
	NegAssertionCache negativeAssertionCache

	//consistencyCache allows to do fast consistency checks.
	ConsistCache consistencyCache

	//redirectCache allows fast retrieval of connection information for a given subjectZone
	RedirectCache redirectionCache
}

func initCaches(config rainsdConfig) *Caches {
	caches := new(Caches)
	caches.ConnCache = &connectionCacheImpl{
		cache:   lruCache.New(),
		counter: safeCounter.New(config.MaxConnections),
	}

	caches.Capabilities = createCapabilityCache(config.CapabilitiesCacheSize)

	caches.ZoneKeyCache = &zoneKeyCacheImpl{
		cache:                lruCache.New(),
		counter:              safeCounter.New(config.ZoneKeyCacheSize),
		warnSize:             config.ZoneKeyCacheWarnSize,
		maxPublicKeysPerZone: config.MaxPublicKeysPerZone,
		keysPerContextZone:   make(map[string]int),
	}

	caches.PendingKeys = &pendingKeyCacheImpl{
		zoneCtxMap: safeHashMap.New(),
		tokenMap:   safeHashMap.New(),
		counter:    safeCounter.New(config.PendingKeyCacheSize),
	}

	caches.PendingQueries = &pendingQueryCacheImpl{
		nameCtxTypesMap: safeHashMap.New(),
		tokenMap:        safeHashMap.New(),
		counter:         safeCounter.New(config.PendingQueryCacheSize),
	}

	caches.AssertionsCache = &assertionCacheImpl{
		cache:                  lruCache.New(),
		counter:                safeCounter.New(config.AssertionCacheSize),
		zoneMap:                safeHashMap.New(),
		entriesPerAssertionMap: make(map[string]int),
	}

	caches.NegAssertionCache = &negativeAssertionCacheImpl{
		cache:   lruCache.New(),
		counter: safeCounter.New(config.NegativeAssertionCacheSize),
		zoneMap: safeHashMap.New(),
	}

	caches.ConsistCache = &consistencyCacheImpl{
		ctxZoneMap: make(map[string]*consistencyCacheValue),
	}

	caches.RedirectCache = &redirectionCacheImpl{
		nameConnMap: lruCache.New(),
		counter:     safeCounter.New(config.RedirectionCacheSize),
		warnSize:    config.RedirectionCacheWarnSize,
	}

	return caches
}

//createCapabilityCache returns a newly created capability cache
func createCapabilityCache(hashToCapCacheSize int) capabilityCache {
	cache := lruCache.New()
	//TODO CFE after there are more capabilities do not use hardcoded value
	cache.GetOrAdd("e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745",
		[]message.Capability{message.TLSOverTCP}, true)
	cache.GetOrAdd("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71",
		[]message.Capability{message.NoCapability}, false)
	counter := safeCounter.New(hashToCapCacheSize)
	counter.Add(2)
	return &capabilityCacheImpl{capabilityMap: cache, counter: counter}
}

func initReapers(config rainsdConfig, caches *Caches, stop chan bool) {
	go reap(func() { caches.ZoneKeyCache.RemoveExpiredKeys() }, config.ReapVerifyTimeout, stop)
	//go reap(func() { revZoneKeyCache.RemoveExpiredKeys() }, config.ReapVerifyTimeout)
	go reap(func() { caches.PendingKeys.RemoveExpiredValues() }, config.ReapVerifyTimeout, stop)
	go reap(func() { caches.RedirectCache.RemoveExpiredValues() }, config.ReapVerifyTimeout, stop)
	go reap(func() { caches.AssertionsCache.RemoveExpiredValues() }, config.ReapEngineTimeout, stop)
	go reap(func() { caches.NegAssertionCache.RemoveExpiredValues() }, config.ReapEngineTimeout, stop)
	go reap(func() { caches.PendingQueries.RemoveExpiredValues() }, config.ReapEngineTimeout, stop)
}

//reap executes reapFunction in intervals of waitTime
func reap(reapFunction func(), waitTime time.Duration, stop chan bool) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		reapFunction()
		time.Sleep(waitTime)
	}
}
