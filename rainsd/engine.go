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
			assertAssertion(section, isAuthoritative)
		}
	case *rainslib.ShardSection:
		if isShardConsistent(section) {
			assertShard(section, isAuthoritative)
		}
	case *rainslib.ZoneSection:
		if isZoneConsistent(section) {
			assertZone(section, isAuthoritative)
		}
	default:
		log.Warn("Unknown message section", "messageSection", section)
	}
}

//assertAssertion adds an assertion to the assertion cache. Triggers any pending queries answered by it.
//The assertion's signatures MUST have already been verified
func assertAssertion(a *rainslib.AssertionSection, isAuthoritative bool) {
	log.Info("Start processing Assertion", "assertion", a)
	if cacheAssertion(a) {
		validFrom, validUntil, ok := getAssertionValidity(a)
		if !ok {
			return //Valid from is too much in the future drop assertion
		}
		assertionsCache.Add(a.Context, a.SubjectZone, a.SubjectName, a.Content[0].Type, isAuthoritative,
			assertionCacheValue{section: a, validFrom: validFrom, validUntil: validUntil})
	}
	//FIXME CFE multiple types per assertion is not handled
	if a.Content[0].Type == rainslib.Delegation {
		//Trigger elements from pendingSignatureCache
		sections, ok := pendingSignatures.GetAllAndDelete(a.Context, a.SubjectZone)
		if ok {
			for _, sectionSender := range sections {
				normalChannel <- msgSectionSender{Section: sectionSender.Section, Sender: sectionSender.Sender, Token: sectionSender.Token}
			}
		}
	}
}

//getAssertionValidity returns validFrom and validUntil for the given assertion upperbounded by the assertion cache maxValidityValue.
//Returns false if validFrom is too much in the future
func getAssertionValidity(a *rainslib.AssertionSection) (int64, int64, bool) {
	validFrom := a.ValidFrom()
	validUntil := a.ValidUntil()
	if validFrom > time.Now().Add(Config.MaxCacheAssertionValidity).Unix() {
		log.Warn("Assertion validity starts too much in the future. Drop Assertion.", "assertion", *a)
		return 0, 0, false
	}
	if validUntil > time.Now().Add(Config.MaxCacheAssertionValidity).Unix() {
		validUntil = time.Now().Add(Config.MaxCacheAssertionValidity).Unix()
		log.Warn("Reduced the validity of the assertion in the cache. Validity exceeded upper bound", "assertion", *a)
	}
	return validFrom, validUntil, true
}

//cacheAssertion returns true if assertion should be cached
func cacheAssertion(assertion *rainslib.AssertionSection) bool {
	log.Info("Assertion will be cached", "assertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//assertShard adds a shard to the negAssertion cache. Trigger any pending queries answered by it
//The shard's signatures and all contained assertion signatures MUST have already been verified
func assertShard(shard *rainslib.ShardSection, isAuthoritative bool) {
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
func assertZone(zone *rainslib.ZoneSection, isAuthoritative bool) {
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
