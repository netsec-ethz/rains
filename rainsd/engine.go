package rainsd

import (
	"rains/rainslib"

	log "github.com/inconshreveable/log15"
)

//assertionCache contains a set of valid assertions where some of them might be expired.
//An entry is marked as extrenal if it might be evicted.
var assertions assertionCache

//negAssertionCache contains for each zone and context an interval tree to find all shards and zones containing a specific assertion
//for a zone the range is infinit: range "",""
//for a shard the range is given as declared in the section.
//An entry is marked as extrenal if it might be evicted.
var negAssertionCache negativeAssertionCache

//pendingQueries contains a mapping from all self issued pending queries to the set of message bodies waiting for it.
//key: <context><subjectzone> value: <msgSection><deadline>
//TODO make the value thread safe. We store a list of <msgSection><deadline> objects which can be added and deleted
var pendingQueries pendingQueryCache

func initEngine() error {
	//init Cache
	/*pendingQueries = &LRUCache{}
	//TODO CFE add size to server config
	err := pendingQueries.New(100)
	if err != nil {
		log.Error("Cannot create pendingQueriesCache", "error", err)
		return err
	}
	//TODO CFE add size to server config
	assertionCache, err = aCache.New(100, "anyContext")
	err = assertionCache.New(100)
	if err != nil {
		log.Error("Cannot create assertionCache", "error", err)
		return err
	}
	negAssertionCache = &LRUCache{}
	//TODO CFE add size to server config
	err = negAssertionCache.New(100)
	if err != nil {
		log.Error("Cannot create assertionCache", "error", err)
		return err
	}*/
	return nil
}

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified
func assert(section rainslib.MessageSectionWithSig, isAuthoritative bool) {
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		if isAssertionConsistent(section) {
			assertAssertion(section)
		}
	case *rainslib.ShardSection:
		if isShardConsistent(section) {
			assertShard(section)
		}
	case *rainslib.ZoneSection:
		if isZoneConsistent(section) {
			assertZone(section)
		}
	default:
		log.Warn("Unknown message section", "messageSection", section)
	}
}

//isAssertionConsistent checks if the incoming assertion is consistent with the elements in the cache. If not every element of this zone is dropped and it return false
func isAssertionConsistent(assertion *rainslib.AssertionSection) bool {
	//make sure that internal assertions are handled properly
	return true
}

//assertAssertion adds an assertion to the assertion cache. Triggers any pending queries answered by it.
//The assertion's signatures MUST have already been verified
func assertAssertion(assertion *rainslib.AssertionSection) {
	log.Info("Start processing Assertion", "assertion", assertion)
	if cacheAssertion(assertion) {
		//add assertion to assertionCache
	}

	//if the assertions' type is delegation then look it up in the pending signatures cache. get queue elements and delete entry, process queue elements. start go routine for
	//each of them, use waitgroup to wait for all of them to finish
}

//cacheAssertion returns true if assertion should be cached
func cacheAssertion(assertion *rainslib.AssertionSection) bool {
	log.Info("Assertion will be cached", "assertion", assertion)
	return true
}

//isShardConsistent checks if the incoming shard is consistent with the elements in the cache. If not every element of this zone is dropped and it return false
func isShardConsistent(assertion *rainslib.ShardSection) bool {
	return true
}

//assertShard adds a shard to the negAssertion cache. Trigger any pending queries answered by it
//The shard's signatures and all contained assertion signatures MUST have already been verified
func assertShard(shard *rainslib.ShardSection) {
	log.Info("Start processing Shard", "shard", shard)
	if cacheShard(shard) {
		//add shard to negCache and assertions to assertionCache
	}
	//check if pending query cache contains sections which are in the range of the shard zone and return all of them and afterwards delete them
	//Process them in separate go routines by checking if the token matches.
	//If so, return the shard to all pending queries on the queue.
	// use waitgroup to synchronize, but only wait at the end of this method.
}

func cacheShard(shard *rainslib.ShardSection) bool {
	log.Info("Shard will be cached", "shard", shard)
	return true
}

//isZoneConsistent checks if the incoming zone is consistent with the elements in the cache. If not every element of this zone is dropped and it return false
func isZoneConsistent(assertion *rainslib.ZoneSection) bool {
	return true
}

//assertZone adds a zone to the negAssertion cache.
//The zone's signatures and all contained shard and assertion signatures MUST have already been verified
func assertZone(zone *rainslib.ZoneSection) {
	log.Info("Start processing zone", "zone", zone)
	if cacheZone(zone) {
		//add contained shards and zone to negCache and contained assertions to assertionCache
	}
	//check if pending query cache contains sections which are in same context and zone, return all of them and afterwards delete them
	//Process them in separate go routines by checking if the token matches.
	//If so, return the shard to all pending queries on the queue.
	//use waitgroup to synchronize, but only wait at the end of this method.
}

func cacheZone(zone *rainslib.ZoneSection) bool {
	log.Info("Zone will be cached", "zone", zone)
	return true
}

//query directly answers the query if result is cached. Otherwise it issues a new query and puts this query to the pendingQueries Cache.
func query(query *rainslib.QuerySection) {
	log.Info("Start processing query", "query", query)
	//if answer is in assertion cache, return assertion (depending on query option also return expired queries)
	//if answer is in negAssertion cache return shard/zone
	//if query option 4 return notification message 504
	//else getDestination (depends on configuration) e.g. for Scion non core AS: core RainsServer, for core AS: redirect?
	////if destination is myself then send notification message 504??
	////if query option 6 then use same token else generate new token
	////add to pending query cache
	////create query and send it out via switchboard
}

//reapEngine deletes expired elements in the following caches: assertionCache, negAssertionCache, pendingQueries
//It sends a 504 notification in case of an expired element in the pendingQueries cache
func reapEngine() {
	//TODO CFE implement once we have datastructure
}
