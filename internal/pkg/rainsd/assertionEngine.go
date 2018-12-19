package rainsd

import (
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

//assert checks the consistency of the incoming section with sections in the cache.
//it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
//The section's signatures MUST have already been verified and there MUST be at least one valid
//rains signature on the message
func (s *Server) assert(ss sectionWithSigSender) {
	log.Debug("Adding section to cache", "section", ss)
	if sectionsAreInconsistent(ss.Sections, s.caches.AssertionsCache, s.caches.NegAssertionCache) {
		log.Warn("section is inconsistent with cached elements.", "sections", ss.Sections)
		sendNotificationMsg(ss.Token, ss.Sender, section.NTRcvInconsistentMsg, "", s)
		return
	}
	//FIXME CFE check if it is authoritative
	addSectionsToCache(ss.Sections, true, s.caches.AssertionsCache,
		s.caches.NegAssertionCache, s.caches.ZoneKeyCache)
	pendingKeysCallback(ss, s.caches.PendingKeys, s.queues.Normal)
	pendingQueriesCallback(ss, s)
	log.Info(fmt.Sprintf("Finished handling %T", ss.Sections), "section", ss.Sections)
}

//sectionsAreInconsistent returns true if at least one section is not consistent with cached element
//which are valid at the same time.
func sectionsAreInconsistent(sec []section.WithSigForward, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache) bool {
	//TODO implement if necessary
	return false
}

//addSectionToCache adds sec to the cache if it comlies with the server's caching policy
func addSectionsToCache(sections []section.WithSigForward, isAuthoritative bool, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache, zoneKeyCache zonePublicKeyCache) {
	for _, sec := range sections {
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
		if shouldAssertionBeCached(sec) {
			a := sec.Copy(zone.Context, zone.SubjectZone)
			addAssertionToCache(a, isAuthoritative, assertionsCache, zoneKeyCache)
		}
		sec.RemoveContextAndSubjectZone()
	}
	negAssertionCache.AddZone(zone, zone.ValidUntil(), isAuthoritative)
	log.Debug("Added zone to cache", "zone", *zone)
}

func pendingKeysCallback(mss sectionWithSigSender, pendingKeys pendingKeyCache, normalChannel chan msgSectionSender) {
	if ss, ok := pendingKeys.GetAndRemove(mss.Token); ok {
		normalChannel <- ss
	}
}

func pendingQueriesCallback(mss sectionWithSigSender, s *Server) {
	msss := s.caches.PendingQueries.GetAndRemove(mss.Token)
	if len(msss) == 0 {
		return
	}
	answer := []section.Section{}
	for _, sec := range mss.Sections {
		answer = append(answer, sec)
	}
	for _, ss := range msss {
		sendSections(answer, ss.Token, ss.Sender, s)
	}
}
