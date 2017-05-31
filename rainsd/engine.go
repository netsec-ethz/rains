package rainsd

import (
	"fmt"
	"rains/rainslib"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//assertionCache contains a set of valid assertions where some of them might be expired.
//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
var assertionsCache assertionCache

//negAssertionCache contains for each zone and context an interval tree to find all shards and zones containing a specific assertion
//for a zone the range is infinit: range "",""
//for a shard the range is given as declared in the section.
//An entry is marked as extrenal if it might be evicted by a LRU caching strategy.
var negAssertionCache negativeAssertionCache

//pendingQueries contains a mapping from all self issued pending queries to the set of message bodies waiting for it.
var pendingQueries pendingQueryCache

//initEngine initialized the engine, which processes valid sections and queries.
//It spawns a goroutine which periodically goes through the cache and removes outdated entries, see reapEngine()
func initEngine() error {
	//init Caches
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

	go reapEngine()

	return nil
}

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified
func assert(sectionWSSender sectionWithSigSender, isAuthoritative bool) {
	switch section := sectionWSSender.Section.(type) {
	case *rainslib.AssertionSection:
		//TODO CFE according to draft consistency checks are only done when server has enough resources. How to measure that?
		log.Info("Start processing Assertion", "assertion", section)
		if isAssertionConsistent(section) {
			log.Debug("Assertion is consistent with cached elements.")
			ok := assertAssertion(section, isAuthoritative, sectionWSSender.Token)
			if ok {
				handleAssertion(section, sectionWSSender.Token)
			}
		} else {
			log.Debug("Assertion is inconsistent with cached elements.")
		}
	case *rainslib.ShardSection:
		log.Info("Start processing Shard", "shard", section)
		if isShardConsistent(section) {
			log.Debug("Shard is consistent with cached elements.")
			ok := assertShard(section, isAuthoritative, sectionWSSender.Token)
			if ok {
				handlePendingQueries(section, sectionWSSender.Token)
			}
		} else {
			log.Debug("Shard is inconsistent with cached elements.")
		}
	case *rainslib.ZoneSection:
		log.Info("Start processing zone", "zone", section)
		if isZoneConsistent(section) {
			log.Debug("Zone is consistent with cached elements.")
			ok := assertZone(section, isAuthoritative, sectionWSSender.Token)
			if ok {
				handlePendingQueries(section, sectionWSSender.Token)
			}
		} else {
			log.Debug("Zone is inconsistent with cached elements.")
		}
	default:
		log.Warn("Unknown message section", "messageSection", section)
	}
	log.Debug(fmt.Sprintf("Finished handling %T", sectionWSSender.Section), "section", sectionWSSender.Section)
}

//assertAssertion adds an assertion to the assertion cache. The assertion's signatures MUST have already been verified.
//TODO CFE only the first element of the assertion is processed
//Returns true if the assertion can be further processed.
func assertAssertion(a *rainslib.AssertionSection, isAuthoritative bool, token rainslib.Token) bool {
	validFrom, validUntil, ok := getAssertionValidity(a)
	if ok {
		if shouldAssertionBeCached(a) {
			value := assertionCacheValue{section: a, validFrom: validFrom, validUntil: validUntil}
			assertionsCache.Add(a.Context, a.SubjectZone, a.SubjectName, a.Content[0].Type, isAuthoritative, value)
			if a.Content[0].Type == rainslib.OTDelegation {
				for _, sig := range a.Signatures {
					if sig.KeySpace == rainslib.RainsKeySpace {
						cacheKey := keyCacheKey{context: a.Context, zone: a.SubjectName, keyAlgo: rainslib.KeyAlgorithmType(sig.Algorithm)}
						publicKey := a.Content[0].Value.(rainslib.PublicKey)
						//FIXME CFE this is just a hack to make it work with ed25519 until we know if we want to remove the type rainslib.Ed25519PublicKey
						array := publicKey.Key.(rainslib.Ed25519PublicKey)
						publicKey.Key = ed25519.PublicKey(array[:])
						publicKey.ValidFrom = validFrom
						publicKey.ValidUntil = validUntil
						log.Debug("Added delegation to cache", "chacheKey", cacheKey, "publicKey", publicKey)
						ok := zoneKeyCache.Add(cacheKey, publicKey, isAuthoritative)
						if !ok {
							log.Warn("Was not able to add entry to zone key cache", "cacheKey", cacheKey, "publicKey", publicKey)
						}
					}

				}
			}
		}
	} else if validFrom < time.Now().Unix() {
		pendingQueries.GetAllAndDelete(token) //assertion cannot be used to answer queries, delete all waiting for this assertion.
		return false
	}
	return true

}

//handleAssertion triggers any pending queries answered by it.
func handleAssertion(a *rainslib.AssertionSection, token rainslib.Token) {
	//FIXME CFE multiple types per assertion is not handled
	if a.Content[0].Type == rainslib.OTDelegation {
		//Trigger elements from pendingSignatureCache
		sections, ok := pendingSignatures.GetAllAndDelete(a.Context, a.SubjectZone)
		if ok {
			for _, sectionSender := range sections {
				normalChannel <- msgSectionSender{Section: sectionSender.Section, Sender: sectionSender.Sender, Token: sectionSender.Token}
			}
		}
	}
	handlePendingQueries(a, token)
}

//handlePendingQueries triggers any pending queries and send the response to it.
func handlePendingQueries(section rainslib.MessageSectionWithSig, token rainslib.Token) {
	//FIXME CFE also allow pending Queries to GetAllAndDelete(zone, type, name,context) because we might get the answer back indirectly.
	values, ok := pendingQueries.GetAllAndDelete(token)
	if ok {
		for _, v := range values {
			if v.validUntil > time.Now().Unix() {
				sendQueryAnswer(section, v.connInfo, v.token)
			} else {
				log.Info("Query expired in pendingQuery queue.", "expirationTime", v.validUntil)
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

//shouldAssertionBeCached returns true if assertion should be cached
func shouldAssertionBeCached(assertion *rainslib.AssertionSection) bool {
	log.Info("Assertion will be cached", "assertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//assertShard adds a shard to the negAssertion cache and all contained assertions to the asseriontsCache.
//The shard's signatures and all contained assertion signatures MUST have already been verified
//Returns true if the shard can be further processed.
func assertShard(shard *rainslib.ShardSection, isAuthoritative bool, token rainslib.Token) bool {
	validFrom, validUntil, ok := getShardValidity(shard)
	if ok {
		if shouldShardBeCached(shard) {
			negAssertionCache.Add(shard.Context, shard.SubjectZone, isAuthoritative, negativeAssertionCacheValue{section: shard, validFrom: validFrom, validUntil: validUntil})
		}
		for _, a := range shard.Content {
			assertAssertion(a, isAuthoritative, [16]byte{})
		}
	} else if validFrom < time.Now().Unix() {
		pendingQueries.GetAllAndDelete(token) //shard cannot be used to answer queries, delete all waiting elements for this shard.
		return false
	}
	return true
}

//getShardValidity returns validFrom and validUntil for the given shard upperbounded by the shard cache maxValidityValue.
//Returns false if validFrom is too much in the future
func getShardValidity(s *rainslib.ShardSection) (int64, int64, bool) {
	validFrom := s.ValidFrom()
	validUntil := s.ValidUntil()
	if validFrom > time.Now().Add(Config.MaxCacheShardValidity).Unix() {
		log.Warn("Shard validity starts too much in the future. Drop Shard.", "shard", *s)
		return 0, 0, false
	}
	if validUntil > time.Now().Add(Config.MaxCacheShardValidity).Unix() {
		validUntil = time.Now().Add(Config.MaxCacheShardValidity).Unix()
		log.Warn("Reduced the validity of the shard in the cache. Validity exceeded upper bound", "shard", *s)
	}
	return validFrom, validUntil, true
}

func shouldShardBeCached(shard *rainslib.ShardSection) bool {
	log.Info("Shard will be cached", "shard", shard)
	//TODO CFE implement when necessary
	return true
}

//assertZone adds a zone to the negAssertion cache. It also adds all contained shards to the negAssertion cache and all contained assertions to the assertionsCache.
//The zone's signatures and all contained shard and assertion signatures MUST have already been verified
//Returns true if the zone can be further processed.
func assertZone(zone *rainslib.ZoneSection, isAuthoritative bool, token rainslib.Token) bool {
	validFrom, validUntil, ok := getZoneValidity(zone)
	if ok {
		if shouldZoneBeCached(zone) {
			negAssertionCache.Add(zone.Context, zone.SubjectZone, isAuthoritative, negativeAssertionCacheValue{section: zone, validFrom: validFrom, validUntil: validUntil})
		}
		for _, v := range zone.Content {
			switch v := v.(type) {
			case *rainslib.AssertionSection:
				assertAssertion(v, isAuthoritative, [16]byte{})
			case *rainslib.ShardSection:
				assertShard(v, isAuthoritative, [16]byte{})
			default:
				log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
			}
		}
	} else if validFrom < time.Now().Unix() {
		pendingQueries.GetAllAndDelete(token) //zone cannot be used to answer queries, delete all waiting elements for this shard.
		return false
	}
	return true
}

//getZoneValidity returns validFrom and validUntil for the given shard upperbounded by the zone cache maxValidityValue.
//Returns false if validFrom is too much in the future
func getZoneValidity(z *rainslib.ZoneSection) (int64, int64, bool) {
	validFrom := z.ValidFrom()
	validUntil := z.ValidUntil()
	if validFrom > time.Now().Add(Config.MaxCacheZoneValidity).Unix() {
		log.Warn("Zone validity starts too much in the future. Drop Zone.", "zone", *z)
		return 0, 0, false
	}
	if validUntil > time.Now().Add(Config.MaxCacheZoneValidity).Unix() {
		validUntil = time.Now().Add(Config.MaxCacheZoneValidity).Unix()
		log.Warn("Reduced the validity of the zone in the cache. Validity exceeded upper bound", "zone", *z)
	}
	return validFrom, validUntil, true
}

func shouldZoneBeCached(zone *rainslib.ZoneSection) bool {
	log.Info("Zone will be cached", "zone", zone)
	//TODO CFE implement when necessary
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
			log.Debug("Finished handling query by sending assertion from cache", "query", query)
			return
		}
	}
	log.Debug("No entry found in assertion cache matching the query")

	for _, zAn := range zoneAndNames {
		negAssertion, ok := negAssertionCache.Get(query.Context, zAn.zone, rainslib.StringInterval{Name: zAn.name})
		if ok {
			sendQueryAnswer(negAssertion, sender, query.Token)
			log.Debug("Finished handling query by sending shard or zone from cache", "query", query)
			return
		}
	}
	log.Debug("No entry found in negAssertion cache matching the query")

	if query.ContainsOption(rainslib.CachedAnswersOnly) {
		log.Debug("Send a notification message back to the sender due to query option: 'Cached Answers only'")
		sendNotificationMsg(query.Token, sender, rainslib.NoAssertionAvail)
		log.Debug("Finished handling query (unsuccessful) ", "query", query)
		return
	}
	for _, zAn := range zoneAndNames {
		delegate := getDelegationAddress(query.Context, zAn.zone)
		if delegate.Equal(serverConnInfo) {
			sendNotificationMsg(query.Token, sender, rainslib.NoAssertionAvail)
			log.Error("Stop processing query. I am authoritative and have no answer in cache")
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
		log.Debug("Added query into to pending query cache", "query", query)
		sendQuery(query.Context, zAn.zone, validUntil, query.Type, token, delegate)
	}
}

//getZoneAndName tries to split a fully qualified name into zone and name
func getZoneAndName(name string) []zoneAndName {
	//TODO CFE use also different heuristics
	names := strings.Split(name, ".")
	zoneAndNames := []zoneAndName{zoneAndName{zone: strings.Join(names[1:], "."), name: names[0]}}
	log.Debug("Split into zone and name", "zone", zoneAndNames[0].zone, "name", zoneAndNames[0].name)
	return zoneAndNames
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
	for {
		assertionsCache.RemoveExpiredValues()
		negAssertionCache.RemoveExpiredValues()
		pendingQueries.RemoveExpiredValues()
		time.Sleep(Config.ReapEngineTimeout)
	}
}
