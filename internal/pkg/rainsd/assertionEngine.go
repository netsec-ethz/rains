package rainsd

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//enoughSystemRessources returns true if the server has enough resources to make consistency checks
var enoughSystemRessources bool

//initEngine initialized the engine, which processes valid sections and queries.
//It spawns a goroutine which periodically goes through the cache and removes outdated entries, see reapEngine()
func initEngine() {
	go measureSystemRessources()
}

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified and there MUST be at least one valid
//rains signature on the message
func (s *Server) assert(ss sectionWithSigSender, isAuthoritative bool) {
	log.Debug("Adding section to cache", "section", ss)
	if enoughSystemRessources && sectionIsInconsistent(ss.Section, s.caches.ConsistCache,
		s.caches.AssertionsCache, s.caches.NegAssertionCache) {
		log.Warn("section is inconsistent with cached elements.", "section", ss.Section)
		sendNotificationMsg(ss.Token, ss.Sender, section.NTRcvInconsistentMsg, "", s)
		return
	}
	addSectionToCache(ss.Section, isAuthoritative, s.caches.AssertionsCache,
		s.caches.NegAssertionCache, s.caches.ZoneKeyCache)
	pendingKeysCallback(ss, s.caches.PendingKeys, s.queues.Normal)
	pendingQueriesCallback(ss, s)
	log.Info(fmt.Sprintf("Finished handling %T", ss.Section), "section", ss.Section)
}

//sectionIsInconsistent returns true if section is not consistent with cached element which are valid
//at the same time.
func sectionIsInconsistent(sec section.WithSig, consistCache consistencyCache,
	assertionsCache assertionCache, negAssertionCache negativeAssertionCache) bool {
	//TODO CFE There are new run time checks. Add Todo's for those that are not yet implemented
	//TODO CFE drop a shard or zone if it is not sorted.
	switch sec := sec.(type) {
	case *section.Assertion:
		return !isAssertionConsistent(sec, consistCache, assertionsCache, negAssertionCache)
	case *section.Shard:
		return !isShardConsistent(sec, consistCache, assertionsCache, negAssertionCache)
	case *section.Zone:
		return !isZoneConsistent(sec, assertionsCache, negAssertionCache)
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
		return true
	}
}

//sectionIsInconsistent returns true if section is not consistent with cached element which are valid
//at the same time.
func addSectionToCache(sec section.WithSig, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	switch sec := sec.(type) {
	case *section.Assertion:
		if shouldAssertionBeCached(sec) {
			addAssertionToCache(sec, isAuthoritative, assertionsCache, zoneKeyCache)
		}
	case *section.Shard:
		if shouldShardBeCached(sec) {
			addShardToCache(sec, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
		}
	case *section.Pshard:
		if shouldPshardBeCached(sec) {
			addPshardToCache(sec, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
		}
	case *section.Zone:
		if shouldZoneBeCached(sec) {
			addZoneToCache(sec, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
		}
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
}

//shouldAssertionBeCached returns true if assertion should be cached
func shouldAssertionBeCached(assertion *section.Assertion) bool {
	log.Info("Assertion will be cached", "assertion", assertion)
	//TODO CFE implement when necessary
	return true
}

//shouldShardBeCached returns true if shard should be cached
func shouldShardBeCached(shard *section.Shard) bool {
	log.Info("Shard will be cached", "shard", shard)
	//TODO CFE implement when necessary
	return true
}

//shouldShardBeCached returns true if shard should be cached
func shouldPshardBeCached(pshard *section.Pshard) bool {
	log.Info("Shard will be cached", "shard", pshard)
	//TODO CFE implement when necessary
	return true
}

//shouldZoneBeCached returns true if zone should be cached
func shouldZoneBeCached(zone *section.Zone) bool {
	log.Info("Zone will be cached", "zone", zone)
	//TODO CFE implement when necessary
	return true
}

//addAssertionToCache adds a to the assertion cache and to the public key cache in case a holds a
//public key.
func addAssertionToCache(a *section.Assertion, isAuthoritative bool, assertionsCache assertionCache,
	zoneKeyCache zonePublicKeyCache) {
	assertionsCache.Add(a, a.ValidUntil(), isAuthoritative)
	log.Debug("Added assertion to cache", "assertion", *a)
	for _, obj := range a.Content {
		if obj.Type == object.OTDelegation {
			if publicKey, ok := obj.Value.(keys.PublicKey); ok {
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
func addShardToCache(shard *section.Shard, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	for _, assertion := range shard.Content {
		if shouldAssertionBeCached(assertion) {
			a := assertion.Copy(shard.Context, shard.SubjectZone)
			addAssertionToCache(a, isAuthoritative, assertionsCache, zoneKeyCache)
		}
		assertion.RemoveContextAndSubjectZone()
	}
	negAssertionCache.AddShard(shard, shard.ValidUntil(), isAuthoritative)
	log.Debug("Added shard to cache", "shard", *shard)
}

//addPshardToCache adds pshard to the negAssertion cache
func addPshardToCache(pshard *section.Pshard, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	negAssertionCache.AddPshard(pshard, pshard.ValidUntil(), isAuthoritative)
	log.Debug("Added pshard to cache", "pshard", *pshard)
}

//addZoneToCache adds zone and all contained shards to the negAssertion cache and all contained
//assertions to the assertionCache.
func addZoneToCache(zone *section.Zone, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *section.Assertion:
			if shouldAssertionBeCached(sec) {
				a := sec.Copy(zone.Context, zone.SubjectZone)
				addAssertionToCache(a, isAuthoritative, assertionsCache, zoneKeyCache)
			}
			sec.RemoveContextAndSubjectZone()
		case *section.Pshard:
			if shouldPshardBeCached(sec) {
				s := sec.Copy(zone.Context, zone.SubjectZone)
				addPshardToCache(s, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
			}
			sec.RemoveContextAndSubjectZone()
		case *section.Shard:
			if shouldShardBeCached(sec) {
				s := sec.Copy(zone.Context, zone.SubjectZone)
				addShardToCache(s, isAuthoritative, assertionsCache, negAssertionCache, zoneKeyCache)
			}
			sec.RemoveContextAndSubjectZone()
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", sec))
		}
	}
	negAssertionCache.AddZone(zone, zone.ValidUntil(), isAuthoritative)
	log.Debug("Added zone to cache", "zone", *zone)
}

func pendingKeysCallback(swss sectionWithSigSender, pendingKeys pendingKeyCache, normalChannel chan msgSectionSender) {
	//TODO CFE also add a section to the queue when an unrelated assertion answers it
	if sectionSenders := pendingKeys.GetAndRemoveByToken(swss.Token); len(sectionSenders) > 0 {
		//An external service MUST check that the received response makes sense. Otherwise these
		//sections would be in the cache as long as the sender responds in time with 'fake' answers
		//(which results in putting these sections on the normal queue from which they are added
		//again to the pending key cache and so forth until the section expires.
		for _, ss := range sectionSenders {
			normalChannel <- msgSectionSender{Sender: ss.Sender, Section: ss.Section, Token: ss.Token}
		}
	}
}

func pendingQueriesCallback(swss sectionWithSigSender, s *Server) {
	//TODO CFE make wait time configurable
	query, ok := s.caches.PendingQueries.GetQuery(swss.Token)
	if !ok {
		//TODO CFE Check by content when token does not match
		return
	}
	if isAnswerToQuery(swss.Section, query) {
		switch section := swss.Section.(type) {
		case *section.Assertion:
			sendAssertionAnswer(section, query, swss.Token, s)
		case *section.Shard:
			sendShardAnswer(section, query, swss.Token, s)
		case *section.Zone:
			sendZoneAnswer(section, query, swss.Token, s)
		default:
			log.Error("Not supported message section with sig. This case must be prevented beforehand")
		}
	}
	//Delegation case
	switch section := swss.Section.(type) {
	case *section.Assertion:
		zoneAndName := fmt.Sprintf("%s.%s", section.SubjectName, section.SubjectZone)
		if iterativeLookupAllowed() {
			if _, ok := object.ContainsType(section.Content, object.OTDelegation); ok {
				if sendToRedirect(zoneAndName, section.Context, swss.Token, query, s) {
					return
				}
			}
			if _, ok := object.ContainsType(section.Content, object.OTRedirection); ok {
				if sendToRedirect(zoneAndName, section.Context, swss.Token, query, s) {
					return
				}
			}
			if o, ok := object.ContainsType(section.Content, object.OTIP6Addr); ok {
				if resendPendingQuery(query, swss.Token, zoneAndName, o.Value.(string),
					time.Now().Add(s.config.QueryValidity).Unix(), s) {
					return
				}
			}
			if o, ok := object.ContainsType(section.Content, object.OTIP4Addr); ok {
				if resendPendingQuery(query, swss.Token, zoneAndName, o.Value.(string),
					time.Now().Add(s.config.QueryValidity).Unix(), s) {
					return
				}
			}
		}
	case *section.Shard, *section.Zone:
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
	sectionSenders, _ := s.caches.PendingQueries.GetAndRemoveByToken(swss.Token, 0)
	for _, ss := range sectionSenders {
		sendNotificationMsg(ss.Token, ss.Sender, section.NTNoAssertionAvail, "", s)
		log.Warn("Was not able to use answer to query.", "query", query, "token", swss.Token,
			"sender", swss.Sender, "section", swss.Section)
	}
}

//isAnswerToQuery returns true if section answers the query.
func isAnswerToQuery(sec section.WithSig, q section.Section) bool {
	switch sec := sec.(type) {
	case *section.Assertion:
		if q, ok := q.(*query.Name); ok {
			if q.Name == fmt.Sprintf("%s.%s", sec.SubjectName, sec.SubjectZone) {
				for _, oType := range q.Types {
					if _, ok := object.ContainsType(sec.Content, oType); ok {
						return true
					}
				}
			}
		}
		return false
	case *section.Shard:
		if q, ok := q.(*query.Name); ok {
			if name, ok := getSubjectName(q.Name, sec.SubjectZone); ok {
				return sec.InRange(name)
			}
		}
		return false
	case *section.Zone:
		if q, ok := q.(*query.Name); ok {
			if _, ok := getSubjectName(q.Name, sec.SubjectZone); ok {
				return true
			}
		}
		return false
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
	return true
}

//getSubjectName returns true and the subjectName of queryName if queryName's suffix is subjectZone
//and queryName != subjectZone is zone. Otherwise an empty string and false is returned
func getSubjectName(queryName, subjectZone string) (string, bool) {
	if strings.HasSuffix(queryName, subjectZone) {
		zonePoints := strings.Count(subjectZone, ".")
		pointDiff := strings.Count(queryName, ".") - zonePoints
		if pointDiff > 0 {
			return strings.Join(strings.Split(queryName, ".")[:pointDiff], "."), true
		}
	}
	return "", false
}

//sendAssertionAnswer sends all assertions arrived during a configurable waitTime back to all
//pending queries waiting on token.
func sendAssertionAnswer(section section.WithSig, query section.Section, token token.Token, s *Server) {
	waitTime := 10 * time.Millisecond
	deadline := time.Now().Add(waitTime).UnixNano()
	s.caches.PendingQueries.AddAnswerByToken(section, token, deadline)
	time.Sleep(waitTime)
	sectionSenders, answers := s.caches.PendingQueries.GetAndRemoveByToken(token, deadline)
	for _, ss := range sectionSenders {
		sendSections(answers, ss.Token, ss.Sender, s)
	}
}

//sendShardAnswer sends either section or contained assertions answering query back to all pending
//queries waiting on token.
func sendShardAnswer(sec *section.Shard, q section.Section, token token.Token, s *Server) {
	name, _ := getSubjectName(q.(*query.Name).Name, sec.SubjectZone)
	answers := sec.AssertionsByNameAndTypes(name, q.(*query.Name).Types)
	sectionSenders, _ := s.caches.PendingQueries.GetAndRemoveByToken(token, 0)
	var secs []section.Section
	if len(answers) > 0 {
		secs = make([]section.Section, len(answers))
		for i := 0; i < len(answers); i++ {
			secs[i] = answers[i]
		}
	} else {
		secs = append(secs, sec)
	}
	for _, ss := range sectionSenders {
		sendSections(secs, ss.Token, ss.Sender, s)
	}
}

//sendZoneAnswer sends either section or contained assertions or shards answering query back to all
//pending queries waiting on token.
func sendZoneAnswer(sec *section.Zone, q section.Section, token token.Token, s *Server) {
	name, _ := getSubjectName(q.(*query.Name).Name, sec.SubjectZone)
	assertions, shards := sec.SectionsByNameAndTypes(name, q.(*query.Name).Types)
	sectionSenders, _ := s.caches.PendingQueries.GetAndRemoveByToken(token, 0)
	var secs []section.Section
	if len(assertions) > 0 {
		secs = make([]section.Section, len(assertions))
		for i := 0; i < len(assertions); i++ {
			secs[i] = assertions[i]
		}
	} else if len(shards) > 0 {
		shortestShard := shards[0]
		for _, s := range shards {
			if len(s.Content) < len(shortestShard.Content) {
				shortestShard = s
			}
		}
		secs = append(secs, shortestShard)
	} else {
		secs = append(secs, sec)
	}
	for _, ss := range sectionSenders {
		sendSections(secs, ss.Token, ss.Sender, s)
	}
}

//sendToRedirect looks up connection information by name in the redirectCache and sends query to it.
//In case there is no connection information stored for name an IP query is sent to a super ordinate
//zone. It then updates token in the redirect cache to the token of the newly sent query.
//Return true if it was able to send a query and update the token
func sendToRedirect(name, context string, oldToken token.Token, q section.Section, s *Server) bool {
	//TODO CFE policy to pick connInfo
	if conns := s.caches.RedirectCache.GetConnsInfo(name); len(conns) > 0 {
		tok := token.New()
		if s.caches.PendingQueries.UpdateToken(oldToken, tok) {
			sendSection(q, tok, conns[0], s)
			return true
		}
		return false
	}
	redirectName := name
	for name != "" {
		if strings.Contains(name, ".") {
			i := strings.Index(name, ".")
			name = name[i+1:]
		} else {
			name = "."
		}
		if conns := s.caches.RedirectCache.GetConnsInfo(name); len(conns) > 0 {
			tok := token.New()
			if s.caches.PendingQueries.UpdateToken(oldToken, tok) {
				newQuery := &query.Name{
					Name:       redirectName,
					Context:    context,
					Expiration: time.Now().Add(s.config.QueryValidity).Unix(),
					Types:      []object.Type{object.OTIP6Addr, object.OTIP4Addr},
				}
				sendSection(newQuery, tok, conns[0], s)
				return true
			}
			return false
		}
	}
	return false
}

//resendPendingQuery resends query to a connInfo retrieved from the redirectCache based on name.
//Token is updated in the cache. ipAddr is the response to a IP query with token. True is returned
//if the token could have been updated in the cache and the new query is sent out.
func resendPendingQuery(query section.Section, oldToken token.Token, name, ipAddr string,
	expiration int64, s *Server) bool {
	//TODO CFE which port to choose?
	if tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:%d", ipAddr, 5022)); err != nil {
		connInfo := connection.Info{Type: connection.TCP, TCPAddr: tcpAddr}
		if s.caches.RedirectCache.AddConnInfo(name, connInfo, expiration) {
			tok := token.New()
			if s.caches.PendingQueries.UpdateToken(oldToken, tok) {
				sendSection(query, tok, connInfo, s)
				return true
			}
		}
		//No redirect/delegation for connInfo in cache, send notification back to senders.
	}
	return false
}

//iterativeLookupAllowed returns true if iterative lookup is enabled for this server
func iterativeLookupAllowed() bool {
	//TODO CFE implement some policy
	return false
}
