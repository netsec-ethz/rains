package rainsd

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/shirou/gopsutil/cpu"
)

//enoughSystemRessources returns true if the server has enough resources to make consistency checks
var enoughSystemRessources bool

//initEngine initialized the engine, which processes valid sections and queries.
//It spawns a goroutine which periodically goes through the cache and removes outdated entries, see reapEngine()
func initEngine() {
	go reapEngine()
	go measureSystemRessources()
}

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified and there MUST be at least one valid
//rains signature on the message
func assert(ss sectionWithSigSender, isAuthoritative bool) {
	if enoughSystemRessources && sectionIsInconsistent(ss.Section) {
		log.Warn("section is inconsistent with cached elements.", "section", ss.Section)
		sendNotificationMsg(ss.Token, ss.Sender, rainslib.NTRcvInconsistentMsg, "")
		return
	}
	addSectionToCache(ss.Section, isAuthoritative)
	pendingKeysCallback(ss)
	pendingQueriesCallback(ss.Token)
	log.Info(fmt.Sprintf("Finished handling %T", ss.Section), "section", ss.Section)
}

//sectionIsInconsistent returns true if section is not consistent with cached element which are valid
//at the same time.
func sectionIsInconsistent(section rainslib.MessageSectionWithSig) bool {
	//FIXME CFE There are new run time checks. Add Todo's for those that are not yet implemented
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		return !isAssertionConsistent(section)
	case *rainslib.ShardSection:
		return !isShardConsistent(section)
	case *rainslib.ZoneSection:
		return !isZoneConsistent(section)
	case *rainslib.AddressAssertionSection:
		return !isAddressAssertionConsistent(section)
	case *rainslib.AddressZoneSection:
		return !isAddressZoneConsistent(section)
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
		return true
	}
}

//sectionIsInconsistent returns true if section is not consistent with cached element which are valid
//at the same time.
func addSectionToCache(section rainslib.MessageSectionWithSig, isAuthoritative bool) {
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		if shouldAssertionBeCached(section) {
			addAssertionToCache(section, isAuthoritative)
		}
	case *rainslib.ShardSection:
		if shouldShardBeCached(section) {
			addShardToCache(section, isAuthoritative)
		}
	case *rainslib.ZoneSection:
		if shouldZoneBeCached(section) {
			addZoneToCache(section, isAuthoritative)
		}
	case *rainslib.AddressAssertionSection:
		if shouldAddressAssertionBeCached(section) {
			addAddressAssertionToCache(section, isAuthoritative)
		}
	case *rainslib.AddressZoneSection:
		if shouldAddressZoneBeCached(section) {
			addAddressZoneToCache(section, isAuthoritative)
		}
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
}

//shouldAssertionBeCached returns true if assertion should be cached
func shouldAssertionBeCached(assertion *rainslib.AssertionSection) bool {
	log.Info("Assertion will be cached", "assertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//shouldShardBeCached returns true if shard should be cached
func shouldShardBeCached(shard *rainslib.ShardSection) bool {
	log.Info("Shard will be cached", "shard", shard)
	//TODO CFE implement when necessary
	return true
}

//shouldZoneBeCached returns true if zone should be cached
func shouldZoneBeCached(zone *rainslib.ZoneSection) bool {
	log.Info("Zone will be cached", "zone", zone)
	//TODO CFE implement when necessary
	return true
}

//shouldAddressAssertionBeCached returns true if assertion should be cached
func shouldAddressAssertionBeCached(assertion *rainslib.AddressAssertionSection) bool {
	log.Info("Assertion will be cached", "AddressAssertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//shouldAddressZoneBeCached returns true if zone should be cached
func shouldAddressZoneBeCached(zone *rainslib.AddressZoneSection) bool {
	log.Info("Zone will be cached", "AddressZone", zone)
	//TODO CFE implement when necessary
	return true
}

//addAssertionToCache adds a to the assertion cache and to the public key cache in case a holds a
//public key.
func addAssertionToCache(a *rainslib.AssertionSection, isAuthoritative bool) {
	assertionsCache.Add(a, a.ValidUntil(), isAuthoritative)
	log.Debug("Added assertion to cache", "assertion", *a)
	for _, obj := range a.Content {
		if obj.Type == rainslib.OTDelegation {
			if publicKey, ok := obj.Value.(rainslib.PublicKey); ok {
				publicKey.ValidSince = a.ValidSince()
				publicKey.ValidUntil = a.ValidUntil()
				ok := zoneKeyCache.Add(a, publicKey, isAuthoritative)
				if !ok {
					log.Warn("number of entries in the zoneKeyCache reached a critical amount")
				}
				log.Debug("Added publicKey to cache", "publicKey", publicKey)
			} else {
				log.Error("Object type and value type mismatch. This case must be prevented beforehand")
			}
		}
	}
}

//addShardToCache adds shard to the negAssertion cache and all contained assertions to the
//assertionsCache.
func addShardToCache(shard *rainslib.ShardSection, isAuthoritative bool) {
	negAssertionCache.AddShard(shard, shard.ValidUntil(), isAuthoritative)
	for _, assertion := range shard.Content {
		a := assertion.Copy(shard.Context, shard.SubjectZone)
		addAssertionToCache(a, isAuthoritative)
	}
}

//addZoneToCache adds zone and all contained shards to the negAssertion cache and all contained
//assertions to the assertionCache.
func addZoneToCache(zone *rainslib.ZoneSection, isAuthoritative bool) {
	negAssertionCache.AddZone(zone, zone.ValidUntil(), isAuthoritative)
	for _, section := range zone.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			a := section.Copy(zone.Context, zone.SubjectZone)
			addAssertionToCache(a, isAuthoritative)
		case *rainslib.ShardSection:
			s := section.Copy(zone.Context, zone.SubjectZone)
			addShardToCache(s, isAuthoritative)
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", section))
		}
	}
}

//addAddressAssertionToCache adds a to the addressSection cache.
func addAddressAssertionToCache(a *rainslib.AddressAssertionSection, isAuthoritative bool) {
	if err := getAddressCache(a.SubjectAddr, a.Context).AddAddressAssertion(a); err != nil {
		log.Warn("Was not able to add addressAssertion to cache", "addressAssertion", a)
	}
}

//addAddressZoneToCache adds zone and all contained addressAssertions to the addressSection cache.
func addAddressZoneToCache(zone *rainslib.AddressZoneSection, isAuthoritative bool) {
	if err := getAddressCache(zone.SubjectAddr, zone.Context).AddAddressZone(zone); err != nil {
		log.Warn("Was not able to add addressZone to cache", "addressZone", zone)
	}
	for _, a := range zone.Content {
		addAddressAssertionToCache(a, isAuthoritative)
	}
}

func pendingKeysCallback(swss sectionWithSigSender) {
	//TODO CFE also add a section to the queue when an unrelated assertion answers it
	if sectionSenders := pendingKeys.GetAndRemoveByToken(swss.Token); len(sectionSenders) > 0 {
		//An external service MUST check that the received response makes sense. Otherwise these
		//sections would be in the cache as long as the sender responds in time with 'fake' answers
		//(which results in putting these sections on the normal queue from which they are added
		//again to the pending key cache and so forth.
		for _, ss := range sectionSenders {
			normalChannel <- msgSectionSender{Sender: ss.Sender, Section: ss.Section, Token: ss.Token}
		}
	}
}

func pendingQueriesCallback(token rainslib.Token) {

}

//handleAssertion triggers any pending queries answered by it. a is already in the cache
func handleAssertion(a *rainslib.AssertionSection, token rainslib.Token) {
	//FIXME CFE new cache should allow to get pending signatures by token. Makes things easier.
	for _, obj := range a.Content {
		if obj.Type == rainslib.OTDelegation {
			sectionSenders, ok := pendingKeys.GetAndRemoveByToken(token)
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
	/*values, ok := pendingQueries.GetAndRemove(section, token, time.Now().Unix())
	log.Debug("handle pending queries.", "waitingQueriesCount", len(values))
	if ok {
		for _, v := range values {
			if v.validUntil > time.Now().Unix() {
				sendOneQueryAnswer(section, v.connInfo, v.token)
			} else {
				log.Info("Query expired in pendingQuery queue.", "expirationTime", v.validUntil)
			}
		}
	}*/
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
	pendingQueries.Add(msgSectionSender{Section: query, Sender: sender, Token: token})
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
			if asserts, ok := assertionsCache.Get(query.Context, zAn.zone, zAn.name, t); ok {
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
		negAssertion, ok := negAssertionCache.Get(query.Context, zAn.zone, rainslib.StringInterval{Name: zAn.name})
		if ok {
			//For each type check if one of the zone or shards contain the queried assertion. If there is at least one assertion answer with it.
			//If no assertion is contained in a zone or shard for any of the queried types, answer with the shortest element. shortest according to what?
			//size in bytes? how to efficiently determine that. e.g. using gob encoding. alternatively we could also count the number of contained elements.
			sendOneQueryAnswer(negAssertion[0], sender, token)
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
		isNew := pendingQueries.Add(msgSectionSender{Section: query, Sender: sender, Token: token})
		log.Info("Added query into to pending query cache", "query", query)
		if isNew {
			msg := rainslib.NewQueryMessage(fmt.Sprintf("%s.%s", zAn.name, zAn.zone), query.Context,
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
