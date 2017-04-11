package rainsd

import (
	"rains/rainslib"

	"strings"

	"time"

	"fmt"

	"container/list"

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

//isAssertionConsistent checks if the incoming assertion is consistent with the elements in the cache.
//If not, every element of this zone and context is dropped and it returns false
func isAssertionConsistent(assertion *rainslib.AssertionSection) bool {
	negAssertions, _ := negAssertionCache.GetAll(assertion.Context, assertion.SubjectZone, assertion)
	for _, negAssertion := range negAssertions {
		switch negAssertion := negAssertion.(type) {
		case *rainslib.ShardSection:
			if !shardContainsAssertion(assertion, negAssertion) {
				dropAllWithContextZone(assertion.Context, assertion.SubjectZone)
				return false
			}
		case *rainslib.ZoneSection:
			if !zoneContainsAssertion(assertion, negAssertion) {
				dropAllWithContextZone(assertion.Context, assertion.SubjectZone)
				return false
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *ZoneSection. Got=%T", negAssertion))
		}
	}
	return true
}

//shardContainsAssertion returns true if the given shard contains the given assertion
func shardContainsAssertion(a *rainslib.AssertionSection, s *rainslib.ShardSection) bool {
	for _, assertion := range s.Content {
		if a.EqualContextZoneName(assertion) {
			return true
		}
	}
	log.Warn("Encountered valid assertion together with a valid shard that does not contain it.", "assertion", *a, "shard", *s)
	return false
}

//zoneContainsAssertion returns true if the given zone contains the given assertion
func zoneContainsAssertion(a *rainslib.AssertionSection, z *rainslib.ZoneSection) bool {
	for _, v := range z.Content {
		switch v := v.(type) {
		case *rainslib.AssertionSection:
			if a.EqualContextZoneName(v) {
				return true
			}
		case *rainslib.ShardSection:
			if shardContainsAssertion(a, v) {
				return true
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
		}
		log.Warn("Encountered valid assertion together with a valid zone that does not contain it.", "assertion", *a, "zone", *z)
	}
	return false
}

//dropAllWithContextZone deletes all assertions, shards and zones in the cache with the given context and zone
func dropAllWithContextZone(context, zone string) {
	assertions, _ := assertionsCache.GetInRange(context, zone, rainslib.TotalInterval{})
	for _, a := range assertions {
		assertionsCache.Remove(a)
	}
	negAssertionCache.Remove(context, zone)
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
func isShardConsistent(shard *rainslib.ShardSection) bool {
	//check against cached assertions
	assertions, ok := assertionsCache.GetInRange(shard.Context, shard.SubjectZone, shard)
	if ok {
		for _, a := range assertions {
			if !shardContainsAssertion(a, shard) {
				dropAllWithContextZone(shard.Context, shard.SubjectZone)
				return false
			}
		}
	}
	//check against cached shards and zones
	sections, ok := negAssertionCache.GetAll(shard.Context, shard.SubjectZone, shard)
	if ok {
		for _, v := range sections {
			switch v := v.(type) {
			case *rainslib.ShardSection:
				if !isShardConsistentWithShard(shard, v) {
					return false
				}
			case *rainslib.ZoneSection:
				if !isShardConsistentWithZone(shard, v) {
					return false
				}
			default:
				log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
			}
		}
	}
	return true
}

//isShardConsistentWithShard returns true if both shards are consistent with each other
func isShardConsistentWithShard(s1, s2 *rainslib.ShardSection) bool {
	v1, ok1 := addAssertionsinRangeToList(s1, s2).Get(s1)
	v2, ok2 := addAssertionsinRangeToList(s2, s1).Get(s2)
	if ok1 != ok2 || len(v1) != len(v2) {
		log.Warn("Shard is not consistent with shard. number of assertions in the intersecting range are different", "shard1", *s1, "shard2", *s2)
		return false
	}
	if ok1 { //there are assertions in the intersection.
		for i := 0; i < len(v1); i++ {
			a1 := v1[i].(*rainslib.AssertionSection)
			a2 := v2[i].(*rainslib.AssertionSection)
			if !a1.EqualContextZoneName(a2) {
				log.Warn("Shard is not consistent with shard. Assertion1 is not equal to assertion2", "shard1", *s1, "shard2", *s2, "assertion1", *a1, "assertion2", a2)
				return false
			}
		}
	}
	return true
}

//isShardConsistentWithZone returns true if the shard is consistent with the zone
func isShardConsistentWithZone(s *rainslib.ShardSection, z *rainslib.ZoneSection) bool {
	assertionsInZone := sectionList{list: list.New()}
	//check that all elements of the zone in the range of the shard are also contained in the shard
	for _, v := range z.Content {
		switch v := v.(type) {
		case *rainslib.AssertionSection:
			if v.SubjectName > s.RangeFrom && v.SubjectName < s.RangeTo {
				if !shardContainsAssertion(v, s) {
					log.Warn("Shard is not consistent with zone. Zone contains assertion in range of shard which is missing in shard")
					return false
				}
			}
			assertionsInZone.Add(v)
		case *rainslib.ShardSection:
			if !isShardConsistentWithShard(v, s) {
				log.Warn("Shard is not consistent with zone. Zone contains shard in range of another shard which are not consistent")
				return false
			}
			for _, a := range v.Content {
				assertionsInZone.Add(a)
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
		}
	}
	//check that all elements of the shard are also contained in the zone.
	for _, a := range s.Content {
		_, ok := assertionsInZone.Get(a)
		if !ok {
			assertions, _ := assertionsInZone.Get(rainslib.TotalInterval{})
			log.Warn("Shard is not consistent with zone. Shard contains an assertion which is not contained in the zone", "zone", z,
				"assertionInZone", assertions, "shard", s)
			return false
		}
	}
	return true
}

//addAssertionsinRangeToList adds all assertions from s1 which are in the range of s2 to the returned rangeQueryDataStruct.
func addAssertionsinRangeToList(s1, s2 *rainslib.ShardSection) rangeQueryDataStruct {
	list := &sectionList{list: list.New()}
	for _, a := range s1.Content {
		if a.SubjectName > s2.RangeFrom && a.SubjectName < s2.RangeTo {
			list.Add(a)
		}
	}
	return list
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
func isZoneConsistent(zone *rainslib.ZoneSection) bool {
	//check against cached assertions
	assertions, _ := assertionsCache.GetInRange(zone.Context, zone.SubjectZone, zone)
	for _, a := range assertions {
		if !zoneContainsAssertion(a, zone) {
			dropAllWithContextZone(zone.Context, zone.SubjectZone)
			return false
		}
	}
	log.Warn("TODO CFE not implemented: Check zone against cached shards and zones")
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
