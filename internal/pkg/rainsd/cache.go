package rainsd

import (
	"github.com/netsec-ethz/rains/internal/pkg/cache"
)

type Caches struct {
	//connCache stores connections of this server. It is not guaranteed that a returned connection is still active.
	ConnCache cache.Connection

	//capabilities stores known hashes of capabilities and for each connInfo what capability the communication partner has.
	Capabilities cache.Capability

	//zoneKeyCache is used to store public keys of zones and a pointer to assertions containing them.
	ZoneKeyCache cache.ZonePublicKey

	//pendingSignatures contains all sections that are waiting for a delegation query to arrive such that their signatures can be verified.
	PendingKeys cache.PendingKey

	//pendingQueries contains a mapping from all self issued pending queries to the set of message bodies waiting for it.
	PendingQueries cache.PendingQuery

	//assertionCache contains a set of valid assertions where some of them might be expired.
	//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
	AssertionsCache cache.Assertion

	//negAssertionCache contains for each zone and context an interval tree to find all shards and zones containing a specific assertion
	//for a zone the range is infinit: range "",""
	//for a shard the range is given as declared in the section.
	//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
	NegAssertionCache cache.NegativeAssertion
}

func initCaches(config rainsdConfig) *Caches {
	caches := new(Caches)
	caches.ConnCache = cache.NewConnection(config.MaxConnections)

	caches.Capabilities = cache.NewCapability(config.CapabilitiesCacheSize)

	caches.ZoneKeyCache = cache.NewZoneKey(config.ZoneKeyCacheSize, config.ZoneKeyCacheWarnSize,
		config.MaxPublicKeysPerZone)

	caches.PendingKeys = cache.NewPendingKey(config.PendingKeyCacheSize)

	caches.PendingQueries = cache.NewPendingQuery(config.PendingQueryCacheSize)

	caches.AssertionsCache = cache.NewAssertion(config.AssertionCacheSize)

	caches.NegAssertionCache = cache.NewNegAssertion(config.NegativeAssertionCacheSize)

	return caches
}

func initReapers(config rainsdConfig, caches *Caches, stop chan bool) {
	go repeatFuncCaller(caches.ZoneKeyCache.RemoveExpiredKeys, config.ReapVerifyTimeout, stop)
	go repeatFuncCaller(caches.PendingKeys.RemoveExpiredValues, config.ReapVerifyTimeout, stop)
	go repeatFuncCaller(caches.AssertionsCache.RemoveExpiredValues, config.ReapEngineTimeout, stop)
	go repeatFuncCaller(caches.NegAssertionCache.RemoveExpiredValues, config.ReapEngineTimeout, stop)
	go repeatFuncCaller(caches.PendingQueries.RemoveExpiredValues, config.ReapEngineTimeout, stop)
}
