package rainsd

import (
	"rains/rainslib"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
)

//assertionCache contains a set of valid assertions where some of them might be expired.
//An entry is marked as extrenal if it might be evicted.
var assertionsCache assertionCache

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
	var err error
	pendingQueries, err = createPendingQueryCache(int(Config.PendingQueryCacheSize))
	if err != nil {
		log.Error("Cannot create pending query Cache", "error", err)
		return err
	}

	assertionsCache, err = createAssertionCache(int(Config.AssertionCacheSize))
	if err != nil {
		log.Error("Cannot create assertion Cache", "error", err)
		return err
	}

	negAssertionCache, err = createNegativeAssertionCache(int(Config.NegativeAssertionCacheSize))
	if err != nil {
		log.Error("Cannot create negative assertion Cache", "error", err)
		return err
	}
	return nil
}

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified
func assert(section rainslib.MessageSectionWithSig, isAuthoritative bool) {
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		//TODO CFE according to draft consistency checks are only done when server has enough resources. How to measure that?
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
func query(query *rainslib.QuerySection, sender ConnInfo) {
	log.Info("Start processing query", "query", query)
	zoneAndNames := getZoneAndName(query.Name)
	for _, zAn := range zoneAndNames {
		assertions, ok := assertionsCache.Get(query.Context, zAn.zone, zAn.name, query.Type, query.ContainsOption(rainslib.ExpiredAssertionsOk))
		//TODO CFE add heuristic which assertion to return
		if ok {
			sendQueryAnswer(assertions[0], sender, query.Token)
			return
		}
	}
	//assertion cache does not contain an answer for this query. Look into negativeAssertion cache
	for _, zAn := range zoneAndNames {
		negAssertion, ok := negAssertionCache.Get(query.Context, zAn.zone, rainslib.StringInterval{Name: zAn.name})
		if ok {
			sendQueryAnswer(negAssertion, sender, query.Token)
			return
		}
	}
	//negativeAssertion cache does not contain an answer for this query.
	if query.ContainsOption(rainslib.CachedAnswersOnly) {
		sendNotificationMsg(query.Token, sender, rainslib.NoAssertionAvail)
		return
	}
	for _, zAn := range zoneAndNames {
		delegate := getDelegationAddress(query.Context, zAn.zone)
		if delegate.Equal(serverConnInfo) {
			sendNotificationMsg(query.Token, sender, rainslib.NoAssertionAvail)
			return
		}
		//we have a valid delegation
		token := query.Token
		if !query.ContainsOption(rainslib.TokenTracing) {
			token = rainslib.GenerateToken()
		}
		validUntil := time.Now().Add(Config.AssertionQueryValidity).Unix() //Upper bound for forwarded query expiration time
		if query.Expires < validUntil {
			validUntil = query.Expires
		}
		pendingQueries.Add(query.Context, zAn.zone, zAn.name, query.Type, pendingQuerySetValue{connInfo: sender, token: token, validUntil: validUntil})
		sendQuery(query.Context, zAn.zone, validUntil, query.Type, token, delegate)
	}
}

//getZoneAndName tries to split a fully qualified name into zone and name
func getZoneAndName(name string) []zoneAndName {
	//TODO CFE use also different heuristics
	names := strings.Split(name, ".")
	return []zoneAndName{zoneAndName{zone: strings.Join(names[1:], "."), name: names[0]}}
}

//sendQueryAnswer sends a section with Signature to back to the sender with the specified token
func sendQueryAnswer(section rainslib.MessageSectionWithSig, sender ConnInfo, token rainslib.Token) {
	//TODO CFE add signature on message?
	msg := rainslib.RainsMessage{Content: []rainslib.MessageSection{section}, Token: token}
	byteMsg, err := msgParser.ParseRainsMsg(msg)
	if err != nil {
		log.Error("Was not able to parse message", "message", msg, "error", err)
		return
	}
	sendTo(byteMsg, sender)
}

//reapEngine deletes expired elements in the following caches: assertionCache, negAssertionCache, pendingQueries
func reapEngine() {
	//TODO CFE implement once we have datastructure
}
