package rainsd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/binaryTrie"

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
	addressCacheIPv4 = make(map[string]addressSectionCache)
	addressCacheIPv4["."] = new(binaryTrie.TrieNode)
	addressCacheIPv6 = make(map[string]addressSectionCache)
	addressCacheIPv6["."] = new(binaryTrie.TrieNode)

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
		log.Debug("Start processing Assertion", "assertion", section)
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
		log.Debug("Start processing Shard", "shard", section)
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
		log.Debug("Start processing zone", "zone", section)
		if isZoneConsistent(section) {
			log.Debug("Zone is consistent with cached elements.")
			ok := assertZone(section, isAuthoritative, sectionWSSender.Token)
			if ok {
				handlePendingQueries(section, sectionWSSender.Token)
			}
		} else {
			log.Debug("Zone is inconsistent with cached elements.")
		}
	case *rainslib.AddressAssertionSection:
		log.Debug("Start processing address assertion", "assertion", section)
		if isAddressAssertionConsistent(section) {
			log.Debug("Address Assertion is consistent with cached elements.")
			ok := assertAddressAssertion(section.Context, section, sectionWSSender.Token)
			if ok {
				handlePendingQueries(section, sectionWSSender.Token)
			}
		} else {
			log.Debug("Address Assertion is inconsistent with cached elements.")
		}
	case *rainslib.AddressZoneSection:
		log.Debug("Start processing address zone", "zone", section)
		if isAddressZoneConsistent(section) {
			log.Debug("Address zone is consistent with cached elements.")
			ok := assertAddressZone(section, sectionWSSender.Token)
			if ok {
				handlePendingQueries(section, sectionWSSender.Token)
			}
		} else {
			log.Debug("Address zone is inconsistent with cached elements.")
		}
	default:
		log.Warn("Unknown message section", "messageSection", section)
	}
	log.Info(fmt.Sprintf("Finished handling %T", sectionWSSender.Section), "section", sectionWSSender.Section)
}

//assertAssertion adds an assertion to the assertion cache. The assertion's signatures MUST have already been verified.
//TODO CFE only the first element of the assertion is processed
//Returns true if the assertion can be used to answer pending queries.
func assertAssertion(a *rainslib.AssertionSection, isAuthoritative bool, token rainslib.Token) bool {
	if shouldAssertionBeCached(a) {
		value := assertionCacheValue{section: a, validSince: a.ValidSince(), validUntil: a.ValidUntil()}
		assertionsCache.Add(a.Context, a.SubjectZone, a.SubjectName, a.Content[0].Type, isAuthoritative, value)
		if a.Content[0].Type == rainslib.OTDelegation {
			if publicKey, ok := a.Content[0].Value.(rainslib.PublicKey); ok {
				cacheKey := keyCacheKey{context: a.Context, zone: a.SubjectName, keyAlgo: publicKey.Type}
				publicKey.ValidSince = a.ValidSince()
				publicKey.ValidUntil = a.ValidUntil()
				log.Debug("Added delegation to cache", "chacheKey", cacheKey, "publicKey", publicKey)
				ok := zoneKeyCache.Add(cacheKey, publicKey, isAuthoritative)
				if !ok {
					log.Warn("Was not able to add entry to zone key cache", "cacheKey", cacheKey, "publicKey", publicKey)
					pendingQueries.GetAllAndDelete(token) //assertion cannot be used to answer queries, delete all waiting for this assertion.
					pendingSignatures.GetAllAndDelete(a.Context, a.SubjectZone)
					return false
				}
			} else {
				log.Warn("Type assertion failed expected a rainslib.PublicKey", "actual", a.Content[0].Value)
				pendingQueries.GetAllAndDelete(token) //assertion cannot be used to answer queries, delete all waiting for this assertion.
				pendingSignatures.GetAllAndDelete(a.Context, a.SubjectZone)
				return false
			}
		}
	}
	if a.ValidSince() > time.Now().Unix() {
		pendingQueries.GetAllAndDelete(token) //assertion cannot be used to answer queries, delete all waiting for this assertion.
		pendingSignatures.GetAllAndDelete(a.Context, a.SubjectZone)
		return false
	}
	return true
}

//handleAssertion triggers any pending queries answered by it.
func handleAssertion(a *rainslib.AssertionSection, token rainslib.Token) {
	//FIXME CFE multiple types per assertion is not handled
	if a.Content[0].Type == rainslib.OTDelegation {
		sections, ok := pendingSignatures.GetAllAndDelete(a.Context, a.SubjectName)
		log.Debug("handle sections from pending signature cache", "waitingSectionCount", len(sections), "subjectZone", a.SubjectName, "context", a.Context)
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
	values, ok := pendingQueries.GetAllAndDelete(token)
	log.Debug("handle pending queries.", "waitingQueriesCount", len(values))
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
		assertAssertion(a, isAuthoritative, [16]byte{})
	}
	if shard.ValidSince() > time.Now().Unix() {
		pendingQueries.GetAllAndDelete(token) //shard cannot be used to answer queries, delete all waiting elements for this shard.
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
			assertAssertion(a, isAuthoritative, [16]byte{})
		case *rainslib.ShardSection:
			s := section.Copy(zone.Context, zone.SubjectZone)
			assertShard(s, isAuthoritative, [16]byte{})
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", section))
		}
	}
	if zone.ValidSince() > time.Now().Unix() {
		pendingQueries.GetAllAndDelete(token) //zone cannot be used to answer queries, delete all waiting elements for this shard.
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
	assertion, zone, ok := getAddressCache(query.SubjectAddr, query.Context).Get(query.SubjectAddr, []rainslib.ObjectType{query.Type})
	//TODO CFE add heuristic which assertion to return
	if ok {
		if assertion != nil {
			sendQueryAnswer(assertion, sender, token)
			log.Debug("Finished handling query by sending address assertion from cache", "query", query)
			return
		}
		if zone != nil && handleAddressZoneQueryResponse(zone, query.SubjectAddr, query.Context,
			query.Type, sender, token) {
			log.Debug("Finished handling query by sending address zone from cache", "query", query)
			return
		}
	}
	log.Debug("No entry found in address cache matching the query")

	if query.ContainsOption(rainslib.QOCachedAnswersOnly) {
		log.Debug("Send a notification message back to the sender due to query option: 'Cached Answers only'")
		sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail)
		log.Debug("Finished handling query (unsuccessful) ", "query", query)
		return
	}

	delegate := getDelegationAddress(query.Context, "")
	if delegate.Equal(serverConnInfo) {
		sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail)
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
	pendingQueries.Add(query.Context, "", "", query.Type, pendingQuerySetValue{connInfo: sender, token: tok, validUntil: validUntil})
	log.Debug("Added query into to pending query cache", "query", query)
	msg := rainslib.NewAddressQueryMessage(query.Context, query.SubjectAddr, validUntil, query.Type, nil, tok)
	SendMessage(msg, delegate)
}

//addressZoneContainsAssertion checks if zone.Content contains an addressAssertion with subjectAddr
//and context. If it does not find an entry it sends the addressZone back to the querier and returns
//true. Otherwise it checks if the entry has an unexpired signature. In that case it sends the
//addressAssertion back to the querier and returns true, otherwise it return false
func handleAddressZoneQueryResponse(zone *rainslib.AddressZoneSection, subjectAddr *net.IPNet,
	context string, queryType rainslib.ObjectType, sender rainslib.ConnInfo, token rainslib.Token) bool {
	for _, a := range zone.Content {
		//TODO CFE handle case where assertion can have multiple types
		if a.SubjectAddr == subjectAddr && a.Context == context && a.Content[0].Type == queryType {
			for _, sig := range a.Sigs(rainslib.RainsKeySpace) {
				//TODO CFE only check for this condition when queryoption 5 is not set
				if sig.ValidUntil > time.Now().Unix() {
					sendQueryAnswer(a, sender, token)
					return true
				}
			}
			return false
		}
	}
	sendQueryAnswer(zone, sender, token)
	return true
}

//query directly answers the query if the result is cached. Otherwise it issues a new query and adds this query to the pendingQueries Cache.
func query(query *rainslib.QuerySection, sender rainslib.ConnInfo, token rainslib.Token) {
	log.Debug("Start processing query", "query", query)
	zoneAndNames := getZoneAndName(query.Name)
	for _, zAn := range zoneAndNames {
		assertions, ok := assertionsCache.Get(query.Context, zAn.zone, zAn.name, query.Type, query.ContainsOption(rainslib.QOExpiredAssertionsOk))
		//TODO CFE add heuristic which assertion to return
		if ok {
			sendQueryAnswer(assertions[0], sender, token)
			log.Info("Finished handling query by sending assertion from cache", "query", query)
			return
		}
		log.Debug("No entry found in assertion cache", "name", zAn.name, "zone", zAn.zone, "context", query.Context, "type", query.Type)
	}

	for _, zAn := range zoneAndNames {
		negAssertion, ok := negAssertionCache.Get(query.Context, zAn.zone, rainslib.StringInterval{Name: zAn.name})
		//FIXME CFE must additionally check that the queried domain is not part of the shard or zone
		//because it might have been already evicted from the assertion cache. In this case send a
		//query and put the current query again on the pending query cache
		if ok {
			sendQueryAnswer(negAssertion, sender, token)
			log.Info("Finished handling query by sending shard or zone from cache", "query", query)
			return
		}
	}
	log.Debug("No entry found in negAssertion cache matching the query")

	if query.ContainsOption(rainslib.QOCachedAnswersOnly) {
		log.Info("Send a notification message back due to query option: 'Cached Answers only'",
			"destination", sender)
		sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail)
		log.Debug("Finished handling query (unsuccessful) ", "query", query)
		return
	}
	for _, zAn := range zoneAndNames {
		delegate := getDelegationAddress(query.Context, zAn.zone)
		if delegate.Equal(serverConnInfo) {
			sendNotificationMsg(token, sender, rainslib.NTNoAssertionAvail)
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
		isNew, _ := pendingQueries.Add(query.Context, zAn.zone, zAn.name, query.Type,
			pendingQuerySetValue{
				connInfo:   sender,
				token:      tok,
				validUntil: validUntil,
			})
		log.Info("Added query into to pending query cache", "query", query)
		if isNew {
			msg := rainslib.NewQueryMessage(query.Context, fmt.Sprintf("%s.%s", zAn.name, zAn.zone),
				validUntil, query.Type, nil, tok)
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
	sendQueryAnswer(section, sender, token)
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
					sendQueryAnswer(a, sender, token)
					return true, true
				}
			}
			return true, false
		}
	}
	return false, false
}

//sendQueryAnswer sends a section with Signature back to the sender with the specified token
func sendQueryAnswer(section rainslib.MessageSectionWithSig, sender rainslib.ConnInfo, token rainslib.Token) {
	//TODO CFE add signature on message?
	msg := rainslib.RainsMessage{Content: []rainslib.MessageSection{section}, Token: token}
	byteMsg, err := msgParser.Encode(msg)
	if err != nil {
		log.Error("Was not able to parse message", "message", msg, "error", err)
		return
	}
	sendTo(byteMsg, sender, 1, 1)
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
