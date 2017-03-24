package rainsd

import (
	"rains/rainslib"

	log "github.com/inconshreveable/log15"
)

//assertionCache contains a set of assertions
var assertionCache Cache

//pendingQueries contains a mapping from all self issued pending queries to the set of message bodies waiting for it.
//key: <keyspace><context><subjectzone> value: <msgSection><deadline>
//TODO make the value thread safe. We store a list of <msgSection><deadline> objects which can be added and deleted
var pendingQueries Cache

func initEngine() {
	var err error
	loadConfig()
	//TODO CFE move to central place
	pendingQueries = &LRUCache{}
	//TODO CFE add size to server config
	err = pendingQueries.New(100)
	if err != nil {
		log.Error("Cannot create pendingQueriesCache", "error", err)
		panic(err)
	}
	assertionCache = &LRUCache{}
	//TODO CFE add size to server config
	err = assertionCache.New(100)
	if err != nil {
		log.Error("Cannot create assertionCache", "error", err)
		panic(err)
	}
}

//Assert adds an message section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The message section's signatures MUST have already been verified
func Assert(section rainslib.MessageSectionWithSig) {
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		assertAssertion(section)
	case *rainslib.ShardSection:
		assertShard(section)
	case *rainslib.ZoneSection:
		assertZone(section)
	default:
		log.Warn("Unknown message section", "messageSection", section)
	}
}

//assertAssertion adds an assertion to the assertion cache. Triggers any pending queries answered by it.
//The assertion's signatures MUST have already been verified
func assertAssertion(assertion *rainslib.AssertionSection) {
	log.Info("Start processing Assertion", "assertion", assertion)
}

//assertShard adds assertions to the assertion cache and shards to the ???ShardCache???. Trigger any pending queries answered by it
//TODO CFE do we need a shardCache?
//The shard's signatures and all contained assertion signatures MUST have already been verified
func assertShard(shard *rainslib.ShardSection) {
	log.Info("Start processing Shard", "shard", shard)
}

//assertZone adds assertions to the assertion cache and shards to the ???ShardCache??? and zone to the ???zoneCache???. Trigger any pending queries answered by it
//TODO CFE do we need a zoneCache?
//The zone's signatures and all contained shard and assertion signatures MUST have already been verified
func assertZone(zone *rainslib.ZoneSection) {
	log.Info("Start processing zone", "zone", zone)
}

//Query directly answers the query if result is cached. Otherwise it issues a new query and puts this query to the pendingQueries Cache.
func Query(query *rainslib.QuerySection) {
	log.Info("Start processing query", "query", query)
}
