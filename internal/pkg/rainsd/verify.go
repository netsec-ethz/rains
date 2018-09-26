package rainsd

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/token"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

//verify verifies msgSender.Section
//It checks the consistency of the msgSender.Section and if it is inconsistent a notification msg is sent. (Consistency with cached elements is checked later in engine)
//It validates all signatures (including contained once), stripping of expired once.
//If no signature remains on an assertion, shard, zone, addressAssertion or addressZone it gets dropped (signatures of contained sections are not taken into account).
//If there happens an error in the signature verification process of any signature, the whole section gets dropped (signatures of contained sections are also considered)
func verify(msgSender msgSectionSender) {
	log.Info(fmt.Sprintf("Verify %T", msgSender.Section), "msgSection", msgSender.Section)
	switch msgSender.Section.(type) {
	case *sections.Assertion, *sections.Shard, *sections.Zone,
		*sections.AddrAssertion:
		sectionSender := sectionWithSigSender{
			Section: msgSender.Section.(sections.SecWithSig),
			Sender:  msgSender.Sender,
			Token:   msgSender.Token,
		}
		verifySection(sectionSender)
	case *sections.AddrQuery, *sections.QueryForward:
		verifyQuery(msgSender.Section.(sections.MessageSectionQuery), msgSender)
	default:
		log.Warn("Not supported Msg section to verify", "msgSection", msgSender)
	}
}

//verifySection forwards the received section protected by signature(s) to be processed if it is
//consistent, all nonexpired signatures verify and there is at least one non expired signature.
func verifySection(sectionSender sectionWithSigSender) {
	if !sectionSender.Section.IsConsistent() {
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, sections.NTRcvInconsistentMsg,
			"contained section has context or subjectZone")
		return //already logged, that contained section is invalid
	}
	if contextInvalid(sectionSender.Section.GetContext()) {
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, sections.NTRcvInconsistentMsg,
			"invalid context")
		return //already logged, that context is invalid
	}
	if zone, ok := sectionSender.Section.(*sections.Zone); ok && !containedShardsAreConsistent(zone) {
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, sections.NTRcvInconsistentMsg,
			"contained sections are inconsistent with outer section")
		return //already logged, that the zone is internally invalid
	}
	if verifySignatures(sectionSender) {
		assert(sectionSender, authoritative[zoneContext{
			Zone:    sectionSender.Section.GetSubjectZone(),
			Context: sectionSender.Section.GetContext(),
		}])
	}
}

//verifyQuery forwards the received query to be processed if it is consistent and not expired.
func verifyQuery(query sections.MessageSectionQuery, msgSender msgSectionSender) {
	if contextInvalid(query.GetContext()) {
		sendNotificationMsg(msgSender.Token, msgSender.Sender, sections.NTRcvInconsistentMsg, "invalid context")
		return //already logged, that context is invalid
	}
	if !isQueryExpired(query.GetExpiration()) {
		processQuery(msgSender)
	}
}

//contextInvalid return true if it is not the global context and the context does not contain a context marker '-cx'.
func contextInvalid(context string) bool {
	if context != "." && !strings.Contains(context, "cx-") {
		log.Warn("Context is malformed.", "context", context)
		return true
	}
	return false
}

//isQueryExpired returns true if the query has expired
func isQueryExpired(expires int64) bool {
	if expires < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", expires, "now", time.Now().Unix())
		return true
	}
	log.Info("Query is not expired")
	return false
}

//verifySignatures verifies all signatures of sectionSender.Section and strips off expired
//signatures. If a public key is missing a query is issued and the section is added to the pending
//key cache. It returns false if there is no signature left on the message or when at least one
//public keys is missing.
func verifySignatures(sectionSender sectionWithSigSender) bool {
	section := sectionSender.Section
	keysNeeded := make(map[signature.MetaData]bool)
	section.NeededKeys(keysNeeded)
	log.Debug("verifySignatures", "KeysNeeded", keysNeeded)
	publicKeys, missingKeys, ok := publicKeysPresent(section.GetSubjectZone(), section.GetContext(), keysNeeded)
	if ok {
		log.Info("All public keys are present.", "msgSectionWithSig", section)
		addZoneAndContextToContainedSections(section)
		return validSignature(section, publicKeys)
	}
	handleMissingKeys(sectionSender, missingKeys)
	return false
}

//publicKeysPresent returns true if all public keys are already cached for sigs.
//It also returns the set of cached publicKeys and a set of the missing publicKey identifiers
func publicKeysPresent(zone, context string, sigMetaData map[signature.MetaData]bool) (
	map[keys.PublicKeyID][]keys.PublicKey, map[signature.MetaData]bool, bool) {
	keys := make(map[keys.PublicKeyID][]keys.PublicKey)
	missingKeys := make(map[signature.MetaData]bool)

	if _, _, err := net.ParseCIDR(zone); err != nil {
		//Assertion, Shard or Zone
		for sigData := range sigMetaData {
			if key, _, ok := zoneKeyCache.Get(zone, context, sigData); ok {
				//returned public key is guaranteed to be valid
				log.Debug("Corresponding Public key in cache.", "cacheKey=sigMetaData", sigData, "publicKey", key)
				keys[sigData.PublicKeyID] = append(keys[sigData.PublicKeyID], key)
			} else {
				log.Debug("Public key not in zoneKeyCache", "zone", zone, "cacheKey=sigMetaData", sigData)
				missingKeys[sigData] = true
			}
		}
	} else {
		//AddressAssertion, AddressZone
		for sigData := range sigMetaData {
			log.Info("Looking for signature with ID", "ID", sigData.PublicKeyID)
			if key, _, ok := revZoneKeyCache.Get(zone, context, sigData); ok {
				//TODO CFE the returned delegation is the most specific one (in terms of its ip
				//address space) in the cache. If it verifies then we add it to the keys slice.
				//Otherwise there might be a delegation to a more specific ip address space and we
				//add it to the missingKeys slice. [Add a CheckSectionSignature function to
				//rainsSiglib which evaluates only one (given) signature]
				log.Debug("Corresponding Public key in cache.", "cacheKey=sigMetaData", sigData, "publicKey", key)
				keys[sigData.PublicKeyID] = append(keys[sigData.PublicKeyID], key)
			} else {
				log.Debug("Public key not in zoneKeyCache", "zone", zone, "cacheKey=sigMetaData", sigData)
				missingKeys[sigData] = true
			}
		}
	}
	return keys, missingKeys, len(missingKeys) == 0
}

//addZoneAndContextToContainedSections adds subjectZone and context to all contained sections.
func addZoneAndContextToContainedSections(section sections.SecWithSig) {
	switch section := section.(type) {
	case *sections.Assertion, *sections.AddrAssertion:
		//no contained sections
	case *sections.Shard:
		section.AddZoneAndContextToAssertions()
	case *sections.Zone:
		section.AddZoneAndContextToSections()
	default:
		log.Warn("Not supported message section with sig")
	}
}

//validSignature validates section's signatures and strips all expired signatures away. Returns
//false if there are no signatures left (not considering internal sections) or if at least one
//signature is invalid (due to incorrect signature)
func validSignature(section sections.SecWithSig, keys map[keys.PublicKeyID][]keys.PublicKey) bool {
	switch section := section.(type) {
	case *sections.Assertion, *sections.AddrAssertion:
		return validateSignatures(section, keys)
	case *sections.Shard:
		return validShardSignatures(section, keys)
	case *sections.Zone:
		return validZoneSignatures(section, keys)
	default:
		log.Warn("Not supported Msg Section")
		return false
	}
}

//validateSignatures returns true if all non expired signatures of section are valid and there is at
//least one signature valid before Config.MaxValidity. It removes valid signatures that are expired
func validateSignatures(section sections.SecWithSig, keyMap map[keys.PublicKeyID][]keys.PublicKey) bool {
	if !siglib.CheckSectionSignatures(section, keyMap, sigEncoder, Config.MaxCacheValidity) {
		return false //already logged
	}
	if section.ValidSince() == math.MaxInt64 {
		log.Info("No signature is valid before the MaxValidity date in the future.")
		return false
	}
	return len(section.Sigs(keys.RainsKeySpace)) > 0
}

//validShardSignatures validates all signatures on the shard and contained assertions. It returns
//false if there is a signatures that does not verify. It removes the context and subjectZone of all
//contained assertions (which were necessary for signature verification)
func validShardSignatures(section *sections.Shard, keys map[keys.PublicKeyID][]keys.PublicKey) bool {
	if !validateSignatures(section, keys) || !validContainedAssertions(section.Content, keys) {
		return false
	}
	return true
}

//validZoneSignatures validates all signatures on the zone and contained assertions and shards. It
//returns false if there is a signatures that does not verify. It removes the subjectZone and
//context of all contained assertions and shards (which were necessary for signature verification)
func validZoneSignatures(zone *sections.Zone, keys map[keys.PublicKeyID][]keys.PublicKey) bool {
	if !validateSignatures(zone, keys) {
		return false
	}
	for _, section := range zone.Content {
		switch sec := section.(type) {
		case *sections.Assertion:
			if !validContainedAssertions([]*sections.Assertion{sec}, keys) {
				return false
			}
		case *sections.Shard:
			if !siglib.CheckSectionSignatures(sec, keys, sigEncoder, Config.MaxCacheValidity) ||
				!validContainedAssertions(sec.Content, keys) {
				return false
			}
			sec.Context = ""
			sec.SubjectZone = ""
		default:
			log.Warn("Unknown message section", "messageSection", zone)
			return false
		}
	}
	return true
}

//validContainedAssertions validates all signatures on assertions. It returns false if there is a
//signature that does not verify. It removes the subjectZone and context of all contained assertions
//(which were necessary for signature verification)
func validContainedAssertions(assertions []*sections.Assertion, keys map[keys.PublicKeyID][]keys.PublicKey) bool {
	for _, assertion := range assertions {
		if !siglib.CheckSectionSignatures(assertion, keys, sigEncoder, Config.MaxCacheValidity) {
			return false
		}
		assertion.Context = ""
		assertion.SubjectZone = ""
	}
	return true
}

//handleMissingKeys adds sectionSender to the pending key cache and sends a delegation query if
//necessary
func handleMissingKeys(sectionSender sectionWithSigSender, missingKeys map[signature.MetaData]bool) {
	section := sectionSender.Section
	log.Info("Some public keys are missing. Add section to pending signature cache",
		"#missingKeys", len(missingKeys), "section", section)
	for k := range missingKeys {
		log.Info("MissingKeys", "key", k)
		if sendQuery := pendingKeys.Add(sectionSender, k.Algorithm, k.KeyPhase); sendQuery {
			token := token.New()
			exp := getQueryValidity(section.Sigs(keys.RainsKeySpace))
			if ok := pendingKeys.AddToken(token, exp, sectionSender.Sender,
				section.GetSubjectZone(), section.GetContext()); ok {
				query := &sections.QueryForward{
					Name:       section.GetSubjectZone(),
					Context:    section.GetContext(),
					Expiration: exp,
					Types:      []object.Type{object.OTDelegation},
				}
				sendSection(query, token, getRootAddr())
				continue
			}
		}
		log.Info("Already issued a delegation query for this context and zone.",
			"zone", section.GetSubjectZone(), "context", section.GetContext())
	}
}

//getQueryValidity returns the expiration value for a delegation query. It is either a configured
//upper bound or if smaller the longest validity time of all present signatures.
func getQueryValidity(sigs []signature.Sig) (validity int64) {
	for _, sig := range sigs {
		if sig.ValidUntil > validity {
			validity = sig.ValidUntil
		}
	}
	//upper bound the validity time
	upperBound := time.Now().Add(Config.DelegationQueryValidity).Unix()
	if validity > upperBound {
		validity = upperBound
	}
	return validity
}
