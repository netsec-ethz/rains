package rainsd

import (
	"fmt"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

// verify verifies msgSender. It checks the consistency of the msgSender.Section and if it is
// inconsistent a notification msg is sent. (Consistency with cached elements is checked later in the
// engine) It validates all signatures (including contained once), stripping of expired once. If no
// signature remains on an assertion, shard, zone, addressAssertion or addressZone it gets dropped
// (signatures of contained sections are not taken into account). If there happens an error in the
// signature verification process of any signature, the whole msgSender gets dropped (signatures of
// contained sections are also considered)
func (s *Server) verify(msgSender util.MsgSectionSender) {
	log.Info(fmt.Sprintf("Verify %T", msgSender.Sections), "server", s.Addr(), "util.MsgSectionSender", msgSender)
	//msgSender.Sections contains either Queries or Assertions. It gets separated in the inbox.
	switch msgSender.Sections[0].(type) {
	case *section.Assertion, *section.Shard, *section.Pshard, *section.Zone:
		isAuthoritative := hasAuthority(msgSender, s)
		if len(s.config.Authorities) != 0 {
			//An authoritative server drops all messages containing sections over which it has no
			//authority and are not a response to a query issued by this server
			if !isAuthoritative && !s.caches.PendingKeys.ContainsToken(msgSender.Token) {
				log.Info("Drop message not part of authority", "msgSender", msgSender)
				return
			}
		}
		verifySections(msgSender, s, isAuthoritative)
	case *query.Name:
		verifyQueries(msgSender, s)
	default:
		log.Warn("Not supported Msg section to verify", "msgSection", msgSender)
	}
}

func hasAuthority(msgSender util.MsgSectionSender, s *Server) bool {
	for _, sec := range msgSender.Sections {
		if !isAuthoritative(sec.(section.WithSigForward), s.config.Authorities) {
			return false
		}
	}
	return true
}

// verifySections first checks the internal consistency of all sections. It then determines if all
// public keys necessary to verify all signatures are present. If not, queries to obtain the missing
// keys are sent and ss is put on the pendingKeyCache. Otherwise all Signatures are verified. As soon
// as one signature is invalid, processing of ss stops. When everything works well, ss is forwarded
// to the engine.
func verifySections(ss util.MsgSectionSender, s *Server, isAuthoritative bool) {
	keys := make(map[keys.PublicKeyID][]keys.PublicKey)
	missingKeys := make(map[missingKeyMetaData]bool)
	for _, sec := range ss.Sections {
		sec := sec.(section.WithSigForward)
		if !sec.IsConsistent() {
			sendNotificationMsg(ss.Token, ss.Sender, section.NTRcvInconsistentMsg,
				"contained section has context or subjectZone", s)
			return //already logged, that contained section is invalid
		}
		if contextInvalid(sec.GetContext()) {
			sendNotificationMsg(ss.Token, ss.Sender, section.NTRcvInconsistentMsg,
				"invalid context", s)
			return //already logged, that context is invalid
		}
		publicKeysPresent(sec, s.caches.ZoneKeyCache, keys, missingKeys)
	}
	if len(missingKeys) != 0 {
		handleMissingKeys(ss, missingKeys, s, isAuthoritative)
		return
	}

	log.Info("All public keys are present.", "msgSectionWithSig", ss.Sections)
	if sections, ok := verifySignatures(ss, keys, s); ok {
		s.assert(util.SectionWithSigSender{
			Sender:   ss.Sender,
			Token:    ss.Token,
			Sections: sections,
		})
		return
	}
	log.Info("Invalid signature")
}

// verifyQueries forwards the received query to be processed if it is consistent and not expired.
func verifyQueries(msgSender util.MsgSectionSender, s *Server) {
	for i, q := range msgSender.Sections {
		q := q.(*query.Name)
		if contextInvalid(q.GetContext()) {
			sendNotificationMsg(msgSender.Token, msgSender.Sender, section.NTRcvInconsistentMsg,
				"invalid context", s)
			return //already logged, that context is invalid
		}
		if isQueryExpired(q.GetExpiration()) {
			msgSender.Sections = append(msgSender.Sections[:i], msgSender.Sections[i+1:]...)
		}
	}
	s.processQuery(msgSender)
}

// contextInvalid return true if it is not the global context and the context does not contain a
// context marker '-cx'.
func contextInvalid(context string) bool {
	if context != "." && !strings.Contains(context, "cx-") {
		log.Warn("Context is malformed.", "context", context)
		return true
	}
	return false
}

// isQueryExpired returns true if the query has expired
func isQueryExpired(expires int64) bool {
	if expires < time.Now().Unix() {
		log.Warn("Query expired", "expirationTime", expires, "now", time.Now().Unix())
		return true
	}
	log.Debug("Query is not expired")
	return false
}

// publicKeysPresent adds all public keys that are cached to keys and for all that are not, the
// corresponding signature meta data is added to missingKeys
func publicKeysPresent(s section.WithSigForward, zoneKeyCache cache.ZonePublicKey,
	keys map[keys.PublicKeyID][]keys.PublicKey, missingKeys map[missingKeyMetaData]bool) {
	keysNeeded := make(map[signature.MetaData]bool)
	s.NeededKeys(keysNeeded)
	for sigData := range keysNeeded {
		if key, _, ok := zoneKeyCache.Get(s.GetSubjectZone(), s.GetContext(), sigData); ok {
			//returned public key is guaranteed to be valid
			log.Debug("Corresponding Public key in cache.", "cacheKey=sigMetaData", sigData, "publicKey", key)
			keys[sigData.PublicKeyID] = append(keys[sigData.PublicKeyID], key)
		} else {
			log.Debug("Public key not in zoneKeyCache", "zone", s.GetSubjectZone(),
				"cacheKey=sigMetaData", sigData)
			missingKeys[missingKeyMetaData{Zone: s.GetSubjectZone(), Context: s.GetContext(),
				KeyPhase: sigData.KeyPhase}] = true
		}
	}
}

// verifySignatures verifies all signatures of ss.Section and strips off expired signatures. It
// returns false if there is no signature left any of the messages
func verifySignatures(ss util.MsgSectionSender, keys map[keys.PublicKeyID][]keys.PublicKey, s *Server) (
	[]section.WithSigForward, bool) {
	sections := []section.WithSigForward{}
	for _, sec := range ss.Sections {
		sec := sec.(section.WithSigForward)
		sections = append(sections, sec)
		if !siglib.CheckSectionSignatures(sec, keys, s.config.MaxCacheValidity) {
			return nil, false
		}
	}
	return sections, true
}

// handleMissingKeys adds sectionSender to the pending key cache and sends a delegation query if
// necessary
func handleMissingKeys(ss util.MsgSectionSender, missingKeys map[missingKeyMetaData]bool, s *Server,
	isAuthoritative bool) {
	sec := ss.Sections
	log.Info("Some public keys are missing. Add section to pending key cache",
		"#missingKeys", len(missingKeys), "sections", ss.Sections)
	exp := getQueryValidity(sec[0].(section.WithSigForward).Sigs(keys.RainsKeySpace),
		s.config.DelegationQueryValidity)
	t := token.New()
	s.caches.PendingKeys.Add(ss, t, exp)
	queries := []section.Section{}
	for k := range missingKeys {
		log.Info("MissingKeys", "key", k)
		queries = append(queries, &query.Name{
			Name:       k.Zone,
			Context:    k.Context,
			Expiration: exp,
			Types:      []object.Type{object.OTDelegation},
			KeyPhase:   k.KeyPhase,
		})
	}
	msg := message.Message{Token: t, Content: queries}
	if isAuthoritative {
		log.Info("Send missing delegation keys to recursive resolver", "msg", msg)
		s.sendToRecursiveResolver(msg)
	} else {
		s.sendTo(msg, ss.Sender, 0, 0)
	}
}

// getQueryValidity returns the expiration value for a delegation query. It is either a configured
// upper bound or if smaller the longest validity time of all present signatures.
func getQueryValidity(sigs []signature.Sig, delegQValidity time.Duration) (validity int64) {
	for _, sig := range sigs {
		if sig.ValidUntil > validity {
			validity = sig.ValidUntil
		}
	}
	//upper bound the validity time
	upperBound := time.Now().Add(delegQValidity).Unix()
	if validity > upperBound {
		validity = upperBound
	}
	return validity
}
