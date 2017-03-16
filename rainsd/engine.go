package rainsd

import (
	"rains/rainslib"

	lru "github.com/hashicorp/golang-lru"
	log "github.com/inconshreveable/log15"
)

//assertionCache contains a set of assertions
//TODO CFE make an interface such that different cache implementation can be used in the future -> same as switchboard
var assertionCache *lru.Cache

//pendinQueries contains a mapping from all self issued pending queries to the set of go routines waiting for it.
//TODO CFE make an interface such that different cache implementation can be used in the future -> same as switchboard
var pendinQueries *lru.Cache

func init() {
	loadConfig()

}

//AssertA adds an assertion to the assertion cache. Triggers any pending queries answered by it.
//The assertion's signatures MUST have already been verified
func AssertA(assertion rainslib.AssertionBody) {
	log.Info("Start processing Assertion", "assertion", assertion)
}

//AssertS adds assertions to the assertion cache and shards to the ???ShardCache???. Trigger any pending queries answered by it
//TODO CFE do we need a shardCache?
//The shard's signatures and all contained assertion signatures MUST have already been verified
func AssertS(shard rainslib.ShardBody) {
	log.Info("Start processing Shard", "shard", shard)
}

//AssertZ adds assertions to the assertion cache and shards to the ???ShardCache??? and zone to the ???zoneCache???. Trigger any pending queries answered by it
//TODO CFE do we need a zoneCache?
//The zone's signatures and all contained shard and assertion signatures MUST have already been verified
func AssertZ(zone rainslib.ZoneBody) {
	log.Info("Start processing zone", "zone", zone)
}

//Query directly answers the query if result is cached. Otherwise it issues a new query and puts this query to the pendingQueries Cache.
func Query(query rainslib.QueryBody) {
	log.Info("Start processing query", "query", query)
}
