package rainsd

import (
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

// assert checks the consistency of the incoming section with sections in the cache.
// it adds a section with valid signatures to the assertion/shard/zone cache. Triggers any pending queries answered by it.
// The section's signatures MUST have already been verified and there MUST be at least one valid
// rains signature on the message
func (s *Server) assert(ss util.SectionWithSigSender) {
	log.Debug("Adding section to cache", "section", ss)
	if sectionsAreInconsistent(ss.Sections, s.caches.AssertionsCache, s.caches.NegAssertionCache) {
		log.Warn("section is inconsistent with cached elements.", "sections", ss.Sections)
		sendNotificationMsg(ss.Token, ss.Sender, section.NTRcvInconsistentMsg, "", s)
		return
	}
	addSectionsToCache(ss.Sections, s.config.Authorities, s.caches.AssertionsCache,
		s.caches.NegAssertionCache, s.caches.ZoneKeyCache)
	pendingKeysCallback(ss, s.caches.PendingKeys, s.queues.Normal)
	pendingQueriesCallback(ss, s)
	log.Info(fmt.Sprintf("Finished handling %T", ss.Sections), "section", ss.Sections)
}

// sectionsAreInconsistent returns true if at least one section is not consistent with cached element
// which are valid at the same time.
func sectionsAreInconsistent(sec []section.WithSigForward, assertionsCache cache.Assertion,
	negAssertionCache cache.NegativeAssertion) bool {
	return false
}

// addSectionToCache adds sec to the cache if it comlies with the server's caching policy
func addSectionsToCache(sections []section.WithSigForward, authorities []ZoneContext,
	assertionsCache cache.Assertion, negAssertionCache cache.NegativeAssertion,
	zoneKeyCache cache.ZonePublicKey) {
	for _, sec := range sections {
		isAuth := isAuthoritative(sec, authorities)
		switch sec := sec.(type) {
		case *section.Assertion:
			if shouldAssertionBeCached(sec) {
				addAssertionToCache(sec, isAuth, assertionsCache, zoneKeyCache)
			}
		case *section.Shard:
			if shouldShardBeCached(sec) {
				addShardToCache(sec, isAuth, assertionsCache, negAssertionCache, zoneKeyCache)
			}
		case *section.Pshard:
			if shouldPshardBeCached(sec) {
				addPshardToCache(sec, isAuth, assertionsCache, negAssertionCache, zoneKeyCache)
			}
		case *section.Zone:
			if shouldZoneBeCached(sec) {
				addZoneToCache(sec, isAuth, assertionsCache, negAssertionCache, zoneKeyCache)
			}
		default:
			log.Error("Not supported message section with sig. This case must be prevented beforehand")
		}
	}
}

// shouldAssertionBeCached returns true if assertion should be cached
func shouldAssertionBeCached(assertion *section.Assertion) bool {
	return len(assertion.Signatures) > 0
}

// shouldShardBeCached returns true if shard should be cached
func shouldShardBeCached(shard *section.Shard) bool {
	log.Info("Shard will be cached", "shard", shard)
	return true
}

// shouldShardBeCached returns true if shard should be cached
func shouldPshardBeCached(pshard *section.Pshard) bool {
	log.Info("Shard will be cached", "shard", pshard)
	return true
}

// shouldZoneBeCached returns true if zone should be cached
func shouldZoneBeCached(zone *section.Zone) bool {
	log.Info("Zone will be cached", "zone", zone)
	return true
}

// addAssertionToCache adds a to the assertion cache and to the public key cache in case a holds a
// public key.
func addAssertionToCache(a *section.Assertion, isAuthoritative bool, assertionsCache cache.Assertion,
	zoneKeyCache cache.ZonePublicKey) {
	assertionsCache.Add(a, a.ValidUntil(), isAuthoritative)
	log.Info("Added assertion to cache", "assertion", *a)
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

// addShardToCache adds shard to the negAssertion cache and all contained assertions to the
// assertionsCache.
func addShardToCache(shard *section.Shard, isAuthoritative bool, assertionsCache cache.Assertion,
	negAssertionCache cache.NegativeAssertion, zoneKeyCache cache.ZonePublicKey) {
	for _, assertion := range shard.Content {
		if shouldAssertionBeCached(assertion) {
			a := assertion.Copy(shard.Context, shard.SubjectZone)
			addAssertionToCache(a, isAuthoritative, assertionsCache, zoneKeyCache)
		}
	}
	negAssertionCache.AddShard(shard, shard.ValidUntil(), isAuthoritative)
	log.Debug("Added shard to cache", "shard", *shard)
}

// addPshardToCache adds pshard to the negAssertion cache
func addPshardToCache(pshard *section.Pshard, isAuthoritative bool, assertionsCache cache.Assertion,
	negAssertionCache cache.NegativeAssertion, zoneKeyCache cache.ZonePublicKey) {
	negAssertionCache.AddPshard(pshard, pshard.ValidUntil(), isAuthoritative)
	log.Debug("Added pshard to cache", "pshard", *pshard)
}

// addZoneToCache adds zone and all contained shards to the negAssertion cache and all contained
// assertions to the assertionCache.
func addZoneToCache(zone *section.Zone, isAuthoritative bool, assertionsCache cache.Assertion,
	negAssertionCache cache.NegativeAssertion, zoneKeyCache cache.ZonePublicKey) {
	for _, assertion := range zone.Content {
		if shouldAssertionBeCached(assertion) {
			a := assertion.Copy(zone.Context, zone.SubjectZone)
			addAssertionToCache(a, isAuthoritative, assertionsCache, zoneKeyCache)
		}
	}
	negAssertionCache.AddZone(zone, zone.ValidUntil(), isAuthoritative)
	log.Debug("Added zone to cache", "zone", *zone)
}

func pendingKeysCallback(mss util.SectionWithSigSender, pendingKeys cache.PendingKey,
	normalChannel chan util.MsgSectionSender) {
	if ss, ok := pendingKeys.GetAndRemove(mss.Token); ok {
		normalChannel <- ss
	}
}

func pendingQueriesCallback(mss util.SectionWithSigSender, s *Server) {
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
