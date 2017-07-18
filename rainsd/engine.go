package rainsd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/binaryTrie"
	"github.com/shirou/gopsutil/cpu"

	log "github.com/inconshreveable/log15"
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

//addressCache contains a set of valid IPv4 address assertions and address zones where some of them might be expired per context.
var addressCacheIPv4 map[string]addressSectionCache

//addressCache contains a set of valid IPv6 address assertions and address zones where some of them might be expired per context.
var addressCacheIPv6 map[string]addressSectionCache

//enoughSystemRessources returns true if the server has enough resources to make consistency checks
var enoughSystemRessources bool

//initEngine initialized the engine, which processes valid sections and queries.
//It spawns a goroutine which periodically goes through the cache and removes outdated entries, see reapEngine()
func initEngine() error {
	//init Caches
	var err error
	pendingQueries, err = createPendingQueryCache(Config.PendingQueryCacheSize)
	if err != nil {
		log.Error("Cannot create pending query Cache", "error", err)
		return err
	}

	assertionsCache, err = createAssertionCache(Config.AssertionCacheSize)
	if err != nil {
		log.Error("Cannot create assertion Cache", "error", err)
		return err
	}

	negAssertionCache, err = createNegativeAssertionCache(Config.NegativeAssertionCacheSize)
	if err != nil {
		log.Error("Cannot create negative assertion Cache", "error", err)
		return err
	}
	//FIXME CFE implement cache according to design document
	addressCacheIPv4 = make(map[string]addressSectionCache)
	addressCacheIPv4["."] = new(binaryTrie.TrieNode)
	addressCacheIPv6 = make(map[string]addressSectionCache)
	addressCacheIPv6["."] = new(binaryTrie.TrieNode)

	go reapEngine()
	go measureSystemRessources()

	return nil
}

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified and there MUST be at least one valid
//rains signature on the message
func assert(sectionWSSender sectionWithSigSender, isAuthoritative bool) {
	switch section := sectionWSSender.Section.(type) {
	case *rainslib.AssertionSection:
		log.Debug("Start processing Assertion", "assertion", section)
		if enoughSystemRessources {
			if !isAssertionConsistent(section) {
				log.Warn("Assertion is inconsistent with cached elements.")
				sendNotificationMsg(sectionWSSender.Token, sectionWSSender.Sender, rainslib.NTBadMessage, "")
				return
			}
		}
		log.Debug("Assertion is consistent with cached elements.")
		ok := assertAssertion(section, isAuthoritative, sectionWSSender.Token)
		if ok {
			handleAssertion(section, sectionWSSender.Token)
		}
	case *rainslib.ShardSection:
		log.Debug("Start processing Shard", "shard", section)
		if enoughSystemRessources {
			if !isShardConsistent(section) {
				log.Debug("Shard is inconsistent with cached elements.")
				sendNotificationMsg(sectionWSSender.Token, sectionWSSender.Sender, rainslib.NTBadMessage, "")
				return
			}
		}
		log.Debug("Shard is consistent with cached elements.")
		ok := assertShard(section, isAuthoritative, sectionWSSender.Token)
		if ok {
			handlePendingQueries(section, sectionWSSender.Token)
		}
	case *rainslib.ZoneSection:
		log.Debug("Start processing zone", "zone", section)
		if enoughSystemRessources {
			if !isZoneConsistent(section) {
				log.Debug("Zone is inconsistent with cached elements.")
				sendNotificationMsg(sectionWSSender.Token, sectionWSSender.Sender, rainslib.NTBadMessage, "")
				return
			}
		}
		log.Debug("Zone is consistent with cached elements.")
		ok := assertZone(section, isAuthoritative, sectionWSSender.Token)
		if ok {
			handlePendingQueries(section, sectionWSSender.Token)
		}
	case *rainslib.AddressAssertionSection:
		log.Debug("Start processing address assertion", "assertion", section)
		if enoughSystemRessources {
			if !isAddressAssertionConsistent(section) {
				log.Debug("Address Assertion is inconsistent with cached elements.")
				sendNotificationMsg(sectionWSSender.Token, sectionWSSender.Sender, rainslib.NTBadMessage, "")
				return
			}
		}
		log.Debug("Address Assertion is consistent with cached elements.")
		ok := assertAddressAssertion(section.Context, section, sectionWSSender.Token)
		if ok {
			handlePendingQueries(section, sectionWSSender.Token)
		}
	case *rainslib.AddressZoneSection:
		log.Debug("Start processing address zone", "zone", section)
		if enoughSystemRessources {
			if !isAddressZoneConsistent(section) {
				log.Debug("Address zone is inconsistent with cached elements.")
				sendNotificationMsg(sectionWSSender.Token, sectionWSSender.Sender, rainslib.NTBadMessage, "")
				return
			}
		}
		log.Debug("Address zone is consistent with cached elements.")
		ok := assertAddressZone(section, sectionWSSender.Token)
		if ok {
			handlePendingQueries(section, sectionWSSender.Token)
		}
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
	log.Info(fmt.Sprintf("Finished handling %T", sectionWSSender.Section), "section", sectionWSSender.Section)
}

//assertAssertion adds an assertion to the assertion cache. The assertion's signatures MUST have already been verified.
//Returns true if the assertion can be used to answer pending queries.
func assertAssertion(a *rainslib.AssertionSection, isAuthoritative bool, token rainslib.Token) bool {
	if shouldAssertionBeCached(a) {
		value := assertionCacheValue{section: a, validSince: a.ValidSince(), validUntil: a.ValidUntil()}
		for i := range a.Content {
			assertionsCache.Add(a.Context, a.SubjectZone, a.SubjectName, a.Content[i].Type, isAuthoritative, value)
			if a.Content[i].Type == rainslib.OTDelegation {
				if publicKey, ok := a.Content[i].Value.(rainslib.PublicKey); ok {
					cacheKey := keyCacheKey{
						zone:        a.SubjectName,
						PublicKeyID: publicKey.PublicKeyID,
					}
					publicKey.ValidSince = a.ValidSince()
					publicKey.ValidUntil = a.ValidUntil()
					ok := zoneKeyCache.Add(cacheKey, publicKey, isAuthoritative)
					if !ok {
						//TODO CFE complain loudly such that an external element can update config, mitigate DDOS, etc.
						log.Warn("Was not able to add entry to zone key cache", "cacheKey", cacheKey, "publicKey", publicKey)
						//delegation assertion cannot be used to answer queries, because cannot store public key. Is this possible in the new cache design?
						pendingQueries.GetAllAndDelete(token)
						pendingSignatures.GetAllAndDelete(a.Context, a.SubjectZone)
						return false
					}
					log.Debug("Added delegation to cache", "chacheKey", cacheKey, "publicKey", publicKey)
				} else {
					log.Error("Object type and value type mismatch. This case must be prevented beforehand")
					return false
				}
			} else if a.Content[i].Type == rainslib.OTRedirection {
				//TODO CFE update Token in cache.
				//special case
				return false
			} else {
				//determine if the response is an answer for the query or an answer to a redirect.
				//return accordingly
			}
		}
	}
	if a.ValidSince() > time.Now().Unix() {
		//assertion cannot be used to answer queries, delete all waiting for this assertion. How should we handle this case.
		//send a redirect to root?
		pendingQueries.GetAllAndDelete(token)
		pendingSignatures.GetAllAndDelete(a.Context, a.SubjectZone)
		return false
	}
	return true
}

//handleAssertion triggers any pending queries answered by it. a is already in the cache
func handleAssertion(a *rainslib.AssertionSection, token rainslib.Token) {
	//FIXME CFE new cache should allow to get pending signatures by token. Makes things easier.
	for _, obj := range a.Content {
		if obj.Type == rainslib.OTDelegation {
			sectionSenders, ok := pendingSignatures.GetAllAndDelete(a.Context, a.SubjectName)
			log.Debug("handle sections from pending signature cache",
				"waitingSectionCount", len(sectionSenders),
				"subjectZone", a.SubjectName,
				"context", a.Context)
			if ok {
				for _, sectionSender := range sectionSenders {
					normalChannel <- msgSectionSender{Section: sectionSender.Section, Sender: sectionSender.Sender, Token: sectionSender.Token}
				}
			}
			break
		}
	}
	handlePendingQueries(a, token)
}

//handlePendingQueries triggers any pending queries and send the response to it.
func handlePendingQueries(section rainslib.MessageSectionWithSig, token rainslib.Token) {
	values, ok := pendingQueries.GetAllAndDelete(token)
	log.Debug("handle pending queries.", "waitingQueriesCount", len(values))
	if ok {
		for _, v := range values {
			if v.validUntil > time.Now().Unix() {
				sendOneQueryAnswer(section, v.connInfo, v.token)
			} else {
				log.Info("Query expired in pendingQuery queue.", "expirationTime", v.validUntil)
			}
		}
	}
}

//shouldAssertionBeCached returns true if assertion should be cached
func shouldAssertionBeCached(assertion *rainslib.AssertionSection) bool {
	log.Info("Assertion will be cached", "assertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//assertShard adds a shard to the negAssertion cache and all contained assertions to the assertionsCache.
//The shard's signatures and all contained assertion signatures MUST have already been verified
//Returns true if the shard can be further processed.
func assertShard(shard *rainslib.ShardSection, isAuthoritative bool, token rainslib.Token) bool {
	if shouldShardBeCached(shard) {
		negAssertionCache.Add(shard.Context, shard.SubjectZone, isAuthoritative,
			negativeAssertionCacheValue{
				section:    shard,
				validSince: shard.ValidSince(),
				validUntil: shard.ValidUntil(),
			})
	}
	for _, assertion := range shard.Content {
		a := assertion.Copy(shard.Context, shard.SubjectZone)
		//TODO CFE how to handle redir assertion in shard which is there for completeness vs redir meant to get further information.
		//also call handleAssertion on all the contained assertions. (in case they are not signed, the server must answer with the whole shard)
		assertAssertion(a, isAuthoritative, [16]byte{})
	}
	//shard cannot be used to answer queries if it and all contained assertions are currently not valid
	//FIXME CFE how to handle this case? 1) delete all waiting elements for this token, 2) send a redirect? 3) redir and blacklist for sender?
	if shard.ValidSince() > time.Now().Unix() {
		pendingQueries.GetAllAndDelete(token)
		return false
	}
	return true
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
	if shouldZoneBeCached(zone) {
		negAssertionCache.Add(zone.Context, zone.SubjectZone, isAuthoritative,
			negativeAssertionCacheValue{
				section:    zone,
				validSince: zone.ValidSince(),
				validUntil: zone.ValidUntil(),
			})
	}
	for _, section := range zone.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			a := section.Copy(zone.Context, zone.SubjectZone)
			//TODO CFE how to handle redir assertion in shard which is there for completeness vs redir meant to get further information.
			//also call handleAssertion on all the contained assertions. (in case they are not signed, the server must answer with the whole shard)
			assertAssertion(a, isAuthoritative, [16]byte{})
		case *rainslib.ShardSection:
			//TODO CFE how to handle redir assertion in shard which is there for completeness vs redir meant to get further information.
			//also call handleAssertion on all the contained assertions. (in case they are not signed, the server must answer with the whole shard)
			s := section.Copy(zone.Context, zone.SubjectZone)
			assertShard(s, isAuthoritative, [16]byte{})
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", section))
		}
	}
	if zone.ValidSince() > time.Now().Unix() {
		//zone cannot be used to answer queries if it and all contained assertion and shards are currently not valid
		//FIXME CFE how to handle this case? 1) delete all waiting elements for this token, 2) send a redirect? 3) redir and blacklist for sender?
		pendingQueries.GetAllAndDelete(token)
		return false
	}
	return true
}

func shouldZoneBeCached(zone *rainslib.ZoneSection) bool {
	log.Info("Zone will be cached", "zone", zone)
	//TODO CFE implement when necessary
	return true
}

//assertAddressAssertion adds an assertion to the address assertion cache. The assertion's signatures MUST have already been verified.
//Returns true if the address assertion can be further processed.
func assertAddressAssertion(context string, a *rainslib.AddressAssertionSection, token rainslib.Token) bool {
	if a.ValidSince() > time.Now().Unix() {
		//TODO CFE similar concerns to the questions for assertions
		pendingQueries.GetAllAndDelete(token) //assertion cannot be used to answer queries, delete all waiting for this assertion.
		return false
	}
	if shouldAddressAssertionBeCached(a) {
		if err := getAddressCache(a.SubjectAddr, context).AddAddressAssertion(a); err != nil {
			log.Warn("Was not able to add addressAssertion to cache", "addressAssertion", a)
		}
	}
	return true
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

//shouldAddressAssertionBeCached returns true if address assertion should be cached
func shouldAddressAssertionBeCached(assertion *rainslib.AddressAssertionSection) bool {
	log.Info("Address Assertion will be cached", "addressAssertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//assertAdressZone adds a zone to the address negAssertion cache. It also adds all contained assertions to the address assertions cache.
//The zone's signatures and all contained assertion signatures MUST have already been verified
//Returns true if the zone can be further processed.
func assertAddressZone(zone *rainslib.AddressZoneSection, token rainslib.Token) bool {
	if zone.ValidSince() > time.Now().Unix() {
		//TODO CFE similar concerns to the questions for shards
		pendingQueries.GetAllAndDelete(token) //address zone cannot be used to answer queries, delete all waiting for this zone.
		return false
	}
	if shouldAddressZoneBeCached(zone) {
		getAddressCache(zone.SubjectAddr, zone.Context).AddAddressZone(zone)
	}
	for _, a := range zone.Content {
		assertAddressAssertion(zone.Context, a, token)
	}
	return true
}

//shouldAddressZoneBeCached returns true if address zone should be cached
func shouldAddressZoneBeCached(zone *rainslib.AddressZoneSection) bool {
	log.Info("Address ZOne will be cached", "addressZone", zone)
	//TODO CFE implement when necessary
	return true
}

//addressQuery directly answers the query if the result is cached. Otherwise it issues a new query
//and adds this query to the pendingQueries Cache.
func addressQuery(query *rainslib.AddressQuerySection, sender rainslib.ConnInfo, token rainslib.Token) {
	log.Debug("Start processing address query", "addressQuery", query)
	assertion, zone, ok := getAddressCache(query.SubjectAddr, query.Context).Get(query.SubjectAddr, query.Types)
	//TODO CFE add heuristic which assertion to return
	if ok {
		if assertion != nil {
			sendOneQueryAnswer(assertion, sender, token)
			log.Debug("Finished handling query by sending address assertion from cache", "query", query)
			return
		}
		if zone != nil && handleAddressZoneQueryResponse(zone, query.SubjectAddr, query.Context,
			query.Types, sender, token) {
			log.Debug("Finished handling query by sending address zone from cache", "query", query)
			return
		}
	}
	log.Debug("No entry found in address cache matching the query")

	if query.ContainsOption(rainslib.QOCachedAnswersOnly) {
		log.Debug("Send a notification message back to the sender due to query option: 'Cached Answers only'")
		sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail, "")
		log.Debug("Finished handling query (unsuccessful) ", "query", query)
		return
	}

	delegate := getRootAddr()
	if delegate.Equal(serverConnInfo) {
		sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail, "")
		log.Error("Stop processing query. I am authoritative and have no answer in cache")
		return
	}
	//we have a valid delegation
	tok := token
	if !query.ContainsOption(rainslib.QOTokenTracing) {
		tok = rainslib.GenerateToken()
	}
	validUntil := time.Now().Add(Config.AddressQueryValidity).Unix() //Upper bound for forwarded query expiration time
	if query.Expires < validUntil {
		validUntil = query.Expires
	}
	//FIXME CFE allow multiple types
	//FIXME CFE only send query if not already in cache.
	pendingQueries.Add(query.Context, "", "", query.Types, pendingQuerySetValue{connInfo: sender, token: tok, validUntil: validUntil})
	log.Debug("Added query into to pending query cache", "query", query)
	msg := rainslib.NewAddressQueryMessage(query.Context, query.SubjectAddr, validUntil, query.Types, nil, tok)
	SendMessage(msg, delegate)
}

//addressZoneContainsAssertion checks if zone.Content contains an addressAssertion with subjectAddr
//and context. If it does not find an entry it sends the addressZone back to the querier and returns
//true. Otherwise it checks if the entry has an unexpired signature. In that case it sends the
//addressAssertion back to the querier and returns true, otherwise it return false
func handleAddressZoneQueryResponse(zone *rainslib.AddressZoneSection, subjectAddr *net.IPNet,
	context string, queryType []rainslib.ObjectType, sender rainslib.ConnInfo, token rainslib.Token) bool {
	for _, a := range zone.Content {
		//TODO CFE handle case where assertion can have multiple types
		if a.SubjectAddr == subjectAddr && a.Context == context && a.Content[0].Type == queryType[0] {
			for _, sig := range a.Sigs(rainslib.RainsKeySpace) {
				//TODO CFE only check for this condition when queryoption 5 is not set
				if sig.ValidUntil > time.Now().Unix() {
					sendOneQueryAnswer(a, sender, token)
					return true
				}
			}
			return false
		}
	}
	sendOneQueryAnswer(zone, sender, token)
	return true
}

//query directly answers the query if the result is cached. Otherwise it issues a new query and adds this query to the pendingQueries Cache.
func query(query *rainslib.QuerySection, sender rainslib.ConnInfo, token rainslib.Token) {
	log.Debug("Start processing query", "query", query)
	zoneAndNames := getZoneAndName(query.Name)
	for _, zAn := range zoneAndNames {
		assertions := []*rainslib.AssertionSection{}
		for _, t := range query.Types {
			asserts, ok := assertionsCache.Get(query.Context, zAn.zone, zAn.name, t, query.ContainsOption(rainslib.QOExpiredAssertionsOk))
			if ok {
				assertions = append(assertions, asserts...)
			}
		}
		//TODO CFE add heuristic which assertion(s) to return
		if len(assertions) > 0 {
			sendOneQueryAnswer(assertions[0], sender, token)
			log.Info("Finished handling query by sending assertion from cache", "query", query)
			return
		}
		log.Debug("No entry found in assertion cache", "name", zAn.name, "zone", zAn.zone, "context", query.Context, "type", query.Types)
	}

	for _, zAn := range zoneAndNames {
		//FIXME CFE this cache should return all shards and zones in the queried interval
		negAssertion, ok := negAssertionCache.Get(query.Context, zAn.zone, rainslib.StringInterval{Name: zAn.name})
		if ok {
			//For each type check if one of the zone or shards contain the queried assertion. If there is at least one assertion answer with it.
			//If no assertion is contained in a zone or shard for any of the queried types, answer with the shortest element. shortest according to what?
			//size in bytes? how to efficiently determine that. e.g. using gob encoding. alternatively we could also count the number of contained elements.
			sendOneQueryAnswer(negAssertion, sender, token)
			log.Info("Finished handling query by sending shard or zone from cache", "query", query)
			return
		}
	}
	log.Debug("No entry found in negAssertion cache matching the query")

	if query.ContainsOption(rainslib.QOCachedAnswersOnly) {
		log.Info("Send a notification message back due to query option: 'Cached Answers only'",
			"destination", sender)
		sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail, "")
		log.Debug("Finished handling query (unsuccessful) ", "query", query)
		return
	}
	for _, zAn := range zoneAndNames {
		//TODO CFE determine if we do the lookup ourselves or if we send a redir assertion back. how
		//to choose redir, just root or more involved strategy? avoid amplification vector. especially if you manage to receive zones. Can saturate a whole link...
		delegate := getRootAddr()
		if delegate.Equal(serverConnInfo) {
			sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail, "")
			log.Error("Stop processing query. I am authoritative and have no answer in cache")
			return
		}
		//we have a valid delegation
		tok := token
		if !query.ContainsOption(rainslib.QOTokenTracing) {
			tok = rainslib.GenerateToken()
		}
		validUntil := time.Now().Add(Config.QueryValidity).Unix() //Upper bound for forwarded query expiration time
		if query.Expires < validUntil {
			validUntil = query.Expires
		}
		isNew, _ := pendingQueries.Add(query.Context, zAn.zone, zAn.name, query.Types,
			pendingQuerySetValue{
				connInfo:   sender,
				token:      tok,
				validUntil: validUntil,
			})
		log.Info("Added query into to pending query cache", "query", query)
		if isNew {
			msg := rainslib.NewQueryMessage(query.Context, fmt.Sprintf("%s.%s", zAn.name, zAn.zone),
				validUntil, query.Types, nil, tok)
			if err := SendMessage(msg, delegate); err == nil {
				log.Info("Sent query.", "destination", delegate, "query", msg.Content[0])
			}
		} else {
			log.Info("Query already sent.")
		}
	}
}

//getZoneAndName tries to split a fully qualified name into zone and name
func getZoneAndName(name string) (zoneAndNames []zoneAndName) {
	//TODO CFE use also different heuristics
	names := strings.Split(name, ".")
	if len(names) == 1 {
		zoneAndNames = []zoneAndName{zoneAndName{zone: ".", name: names[0]}}
	} else {
		zoneAndNames = []zoneAndName{zoneAndName{zone: strings.Join(names[1:], "."), name: names[0]}}
	}
	log.Debug("Split into zone and name", "zone", zoneAndNames[0].zone, "name", zoneAndNames[0].name)
	return zoneAndNames
}

//handleShardOrZoneQueryResponse checks if section.Content contains an assertion with subjectName,
//subjectZone and context. If it does not find an entry it sends the section back to the querier and
//returns true. Otherwise it checks if the entry has an unexpired signature. In that case it sends
//the assertion back to the querier and returns true, otherwise it return false
func handleShardOrZoneQueryResponse(section rainslib.MessageSectionWithSigForward, subjectName, subjectZone,
	context string, queryType rainslib.ObjectType, sender rainslib.ConnInfo, token rainslib.Token) bool {
	assertions := []*rainslib.AssertionSection{}
	switch section := section.(type) {
	case *rainslib.ShardSection:
		assertions = section.Content
	case *rainslib.ZoneSection:
		for _, sec := range section.Content {
			switch sec := sec.(type) {
			case *rainslib.AssertionSection:
				assertions = append(assertions, sec)
			case *rainslib.ShardSection:
				assertions = append(assertions, sec.Content...)
			default:
				log.Warn(fmt.Sprintf("Unsupported zone.Content Expected assertion or shard. actual=%T", section))
			}
		}
	default:
		log.Warn(fmt.Sprintf("Unexpected MessageSectionWithSigForward. Expected zone or shard. actual=%T", section))
	}
	if entryFound, hasSig := containedAssertionQueryResponse(assertions, subjectName,
		subjectZone, context, queryType, sender, token); entryFound {
		return hasSig
	}
	sendOneQueryAnswer(section, sender, token)
	return true
}

//containedAssertionQueryResponse checks if assertions contains an assertion with subjectName,
//subjectZone and context. If it does not find an entry it returns (false, false). Otherwise it
//checks if the entry has an unexpired signature. In that case it sends the assertion back to the
//querier and returns (true, true), otherwise it return (true, false)
func containedAssertionQueryResponse(assertions []*rainslib.AssertionSection, subjectName, subjectZone,
	context string, queryType rainslib.ObjectType, sender rainslib.ConnInfo, token rainslib.Token) (
	entryFound bool, hasSig bool) {
	for _, a := range assertions {
		//TODO CFE handle case where assertion can have multiple types
		if a.SubjectName == subjectName && a.SubjectZone == subjectZone &&
			a.Context == context && a.Content[0].Type == queryType {
			for _, sig := range a.Sigs(rainslib.RainsKeySpace) {
				//TODO CFE only check for this condition when queryoption 5 is not set
				if sig.ValidUntil > time.Now().Unix() {
					sendOneQueryAnswer(a, sender, token)
					return true, true
				}
			}
			return true, false
		}
	}
	return false, false
}

//sendQueryAnswer sends a slice of sections with Signatures back to the sender with the specified token
func sendQueryAnswer(sections []rainslib.MessageSection, sender rainslib.ConnInfo, token rainslib.Token) {
	SendMessage(rainslib.RainsMessage{Content: sections, Token: token}, sender)
}

//sendOneQueryAnswer sends a section with Signature back to the sender with the specified token
func sendOneQueryAnswer(section rainslib.MessageSectionWithSig, sender rainslib.ConnInfo, token rainslib.Token) {
	sendQueryAnswer([]rainslib.MessageSection{section}, sender, token)
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

//measureSystemRessources measures current cpu usage and updates enoughSystemRessources
//TODO CFE make it configurable, experiment with different sampling rates
func measureSystemRessources() {
	for {
		cpuStat, _ := cpu.Percent(time.Second/10, false)
		enoughSystemRessources = cpuStat[0] < 75
		if !enoughSystemRessources {
			log.Warn("Not enough system resources to check for consistency")
		}
		time.Sleep(time.Second * 10)
	}
}
