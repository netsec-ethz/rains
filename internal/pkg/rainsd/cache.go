package rainsd

import (
	"net"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/binaryTrie"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
)

//connCache stores connections of this server. It is not guaranteed that a returned connection is still active.
var connCache connectionCache

//capabilities stores known hashes of capabilities and for each connInfo what capability the communication partner has.
var capabilities capabilityCache

//zoneKeyCache is used to store public keys of zones and a pointer to assertions containing them.
var zoneKeyCache zonePublicKeyCache

//revZoneKeyCache is used to store public keys of addressZones and a pointer to delegation
//assertions containing them.
//TODO CFE implement it
var revZoneKeyCache revZonePublicKeyCache

//pendingSignatures contains all sections that are waiting for a delegation query to arrive such that their signatures can be verified.
var pendingKeys pendingKeyCache

//pendingQueries contains a mapping from all self issued pending queries to the set of message bodies waiting for it.
var pendingQueries pendingQueryCache

//assertionCache contains a set of valid assertions where some of them might be expired.
//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
var assertionsCache *assertionCacheImpl

//negAssertionCache contains for each zone and context an interval tree to find all shards and zones containing a specific assertion
//for a zone the range is infinit: range "",""
//for a shard the range is given as declared in the section.
//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
var negAssertionCache negativeAssertionCache

//consistencyCache allows to do fast consistency checks.
var consistCache consistencyCache

//redirectCache allows fast retrieval of connection information for a given subjectZone
var redirectCache redirectionCache

//addressCache contains a set of valid IPv4 address assertions and address zones where some of them might be expired per context.
var addressCacheIPv4 map[string]addressSectionCache

//addressCache contains a set of valid IPv6 address assertions and address zones where some of them might be expired per context.
var addressCacheIPv6 map[string]addressSectionCache

func initCaches() {
	connCache = &connectionCacheImpl{
		cache:   lruCache.New(),
		counter: safeCounter.New(Config.MaxConnections),
	}

	capabilities = createCapabilityCache(Config.CapabilitiesCacheSize)

	zoneKeyCache = &zoneKeyCacheImpl{
		cache:                lruCache.New(),
		counter:              safeCounter.New(Config.ZoneKeyCacheSize),
		warnSize:             Config.ZoneKeyCacheWarnSize,
		maxPublicKeysPerZone: Config.MaxPublicKeysPerZone,
		keysPerContextZone:   make(map[string]int),
	}

	pendingKeys = &pendingKeyCacheImpl{
		zoneCtxMap: safeHashMap.New(),
		tokenMap:   safeHashMap.New(),
		counter:    safeCounter.New(Config.PendingKeyCacheSize),
	}

	pendingQueries = &pendingQueryCacheImpl{
		nameCtxTypesMap: safeHashMap.New(),
		tokenMap:        safeHashMap.New(),
		counter:         safeCounter.New(Config.PendingQueryCacheSize),
	}

	assertionsCache = &assertionCacheImpl{
		cache:                  lruCache.New(),
		counter:                safeCounter.New(Config.AssertionCacheSize),
		zoneMap:                safeHashMap.New(),
		entriesPerAssertionMap: make(map[string]int),
	}

	negAssertionCache = &negativeAssertionCacheImpl{
		cache:   lruCache.New(),
		counter: safeCounter.New(Config.NegativeAssertionCacheSize),
		zoneMap: safeHashMap.New(),
	}

	consistCache = &consistencyCacheImpl{
		ctxZoneMap: make(map[string]*consistencyCacheValue),
	}

	redirectCache = &redirectionCacheImpl{
		nameConnMap: lruCache.New(),
		counter:     safeCounter.New(Config.RedirectionCacheSize),
		warnSize:    Config.RedirectionCacheWarnSize,
	}

	//FIXME CFE implement cache according to design document
	addressCacheIPv4 = make(map[string]addressSectionCache)
	addressCacheIPv4["."] = new(binaryTrie.TrieNode)
	addressCacheIPv6 = make(map[string]addressSectionCache)
	addressCacheIPv6["."] = new(binaryTrie.TrieNode)

	go reap(func() { zoneKeyCache.RemoveExpiredKeys() }, Config.ReapVerifyTimeout)
	//go reap(func() { revZoneKeyCache.RemoveExpiredKeys() }, Config.ReapVerifyTimeout)
	go reap(func() { pendingKeys.RemoveExpiredValues() }, Config.ReapVerifyTimeout)
	go reap(func() { redirectCache.RemoveExpiredValues() }, Config.ReapVerifyTimeout)
	go reap(func() { assertionsCache.RemoveExpiredValues() }, Config.ReapEngineTimeout)
	go reap(func() { negAssertionCache.RemoveExpiredValues() }, Config.ReapEngineTimeout)
	go reap(func() { pendingQueries.RemoveExpiredValues() }, Config.ReapEngineTimeout)
}

//reap executes reapFunction in intervals of waitTime
func reap(reapFunction func(), waitTime time.Duration) {
	for {
		reapFunction()
		time.Sleep(waitTime)
	}
}

func getAddressCache(addr *net.IPNet, context string) (tree addressSectionCache) {
	if addr.IP.To4() != nil {
		tree = addressCacheIPv4[context]
		if tree == nil {
			tree = new(binaryTrie.TrieNode)
			addressCacheIPv4[context] = tree
		}
	} else {
		tree = addressCacheIPv6[context]
		if tree == nil {
			tree = new(binaryTrie.TrieNode)
			addressCacheIPv6[context] = tree
		}
	}
	return
}
