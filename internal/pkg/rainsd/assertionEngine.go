package rainsd

import (
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified and there MUST be at least one valid
//rains signature on the message
func (s *Server) assert(ss sectionWithSigSender, isAuthoritative bool) {
	log.Debug("Adding section to cache", "section", ss)
	if sectionIsInconsistent(ss.Section, s.caches.AssertionsCache, s.caches.NegAssertionCache) {
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

//sectionIsInconsistent returns true if section is not consistent with cached element which are
//valid at the same time.
func sectionIsInconsistent(sec section.WithSig, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache) bool {
	//TODO implement if necessary
	return false
}

//addSectionToCache adds sec to the cache if it comlies with the server's caching policy
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
			publicKey, _ := obj.Value.(keys.PublicKey)
			publicKey.ValidSince = a.ValidSince()
			publicKey.ValidUntil = a.ValidUntil()
			ok := zoneKeyCache.Add(a, publicKey, isAuthoritative)
			if !ok {
				log.Warn("number of entries in the zoneKeyCache reached a critical amount")
			}
			log.Debug("Added publicKey to cache", "publicKey", publicKey)
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
	if sectionSenders := pendingKeys.GetAndRemoveByToken(swss.Token); len(sectionSenders) > 0 {
		for _, ss := range sectionSenders {
			normalChannel <- msgSectionSender{Sender: ss.Sender, Section: ss.Section, Token: ss.Token}
		}
	}
}

func pendingQueriesCallback(swss sectionWithSigSender, s *Server) {
	newDeadline := time.Now().Add(50 * time.Microsecond).Unix()
	if ok := s.caches.PendingQueries.AddAnswerByToken(swss.Section, swss.Token, newDeadline); !ok {
		return //Already answered by another incoming assertion.
	}
	queries, _ := s.caches.PendingQueries.GetAndRemoveByToken(swss.Token, newDeadline)
	for _, ss := range queries {
		sendSection(swss.Section, ss.Token, ss.Sender, s)
	}
}
