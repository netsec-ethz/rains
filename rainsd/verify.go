package rainsd

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
)

//sigEncoder is used to translate a message or section into a signable format
var sigEncoder rainslib.SignatureFormatEncoder

//verify verifies msgSender.Section
//It checks the consistency of the msgSender.Section and if it is inconsistent a notification msg is sent. (Consistency with cached elements is checked later in engine)
//It validates all signatures (including contained once), stripping of expired once.
//If no signature remains on an assertion, shard, zone, addressAssertion or addressZone it gets dropped (signatures of contained sections are not taken into account).
//If there happens an error in the signature verification process of any signature, the whole section gets dropped (signatures of contained sections are also considered)
func verify(msgSender msgSectionSender) {
	log.Info(fmt.Sprintf("Verify %T", msgSender.Section), "msgSection", msgSender.Section)
	switch msgSender.Section.(type) {
	case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection,
		*rainslib.AddressAssertionSection, *rainslib.AddressZoneSection:
		sectionSender := sectionWithSigSender{
			Section: msgSender.Section.(rainslib.MessageSectionWithSig),
			Sender:  msgSender.Sender,
			Token:   msgSender.Token,
		}
		verifySection(sectionSender)
	case *rainslib.AddressQuerySection, *rainslib.QuerySection:
		verifyQuery(msgSender.Section.(rainslib.MessageSectionQuery), msgSender)
	default:
		log.Warn("Not supported Msg section to verify", "msgSection", msgSender)
	}
}

//verifySection forwards the received section protected by signature(s) to be processed if it is
//consistent, all nonexpired signatures verify and there is at least one non expired signature.
func verifySection(sectionSender sectionWithSigSender) {
	if !sectionSender.Section.IsConsistent() {
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
		return //already logged, that contained section is invalid
	}
	if contextInvalid(sectionSender.Section.GetContext()) {
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
		return //already logged, that context is invalid
	}
	if zone, ok := sectionSender.Section.(*rainslib.ZoneSection); ok && !containedShardsAreConsistent(zone) {
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
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
func verifyQuery(query rainslib.MessageSectionQuery, msgSender msgSectionSender) {
	if contextInvalid(query.GetContext()) {
		sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTRcvInconsistentMsg, "")
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
	keysNeeded := make(map[rainslib.SignatureMetaData]bool)
	neededKeys(section, keysNeeded)
	publicKeys, missingKeys, ok := publicKeysPresent(section.GetSubjectZone(), section.GetContext(), keysNeeded)
	if ok {
		log.Info("All public keys are present.", "msgSectionWithSig", section)
		addZoneAndContextToContainedSections(section)
		return validSignature(section, publicKeys)
	}
	handleMissingKeys(sectionSender, missingKeys)
	return false
}

//neededKeys returns the set of public key identifiers necessary to verify all signatures on the section and all contained sections.
func neededKeys(section rainslib.MessageSectionWithSig, keys map[rainslib.SignatureMetaData]bool) {
	switch section := section.(type) {
	case *rainslib.AssertionSection, *rainslib.AddressAssertionSection:
		extractNeededKeys(section, keys)
	case *rainslib.ShardSection:
		extractNeededKeys(section, keys)
		for _, a := range section.Content {
			extractNeededKeys(a, keys)
		}
	case *rainslib.ZoneSection:
		extractNeededKeys(section, keys)
		for _, sec := range section.Content {
			neededKeys(sec, keys)
		}
	case *rainslib.AddressZoneSection:
		extractNeededKeys(section, keys)
		for _, a := range section.Content {
			extractNeededKeys(a, keys)
		}
	default:
		log.Error("Not supported message section with sig. This case must be prevented beforehand")
	}
}

//extractNeededKeys adds all key metadata to keys which are necessary to verify all section's signatures
func extractNeededKeys(section rainslib.MessageSectionWithSig, sigData map[rainslib.SignatureMetaData]bool) {
	for _, sig := range section.Sigs(rainslib.RainsKeySpace) {
		sigData[sig.GetSignatureMetaData()] = true
	}
}

//publicKeysPresent returns true if all public keys are already cached for sigs.
//It also returns the set of cached publicKeys and a set of the missing publicKey identifiers
func publicKeysPresent(zone, context string, sigMetaData map[rainslib.SignatureMetaData]bool) (
	map[rainslib.PublicKeyID][]rainslib.PublicKey, map[rainslib.SignatureMetaData]bool, bool) {
	keys := make(map[rainslib.PublicKeyID][]rainslib.PublicKey)
	missingKeys := make(map[rainslib.SignatureMetaData]bool)

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
func addZoneAndContextToContainedSections(section rainslib.MessageSectionWithSig) {
	switch section := section.(type) {
	case *rainslib.AssertionSection, *rainslib.AddressAssertionSection:
		//no contained sections
	case *rainslib.ShardSection:
		section.AddZoneAndContextToAssertions()
	case *rainslib.ZoneSection:
		section.AddZoneAndContextToSections()
	case *rainslib.AddressZoneSection:
		for _, a := range section.Content {
			a.Context = section.Context
		}
	default:
		log.Warn("Not supported message section with sig")
	}
}

//handleMissingKeys adds sectionSender to the pending key cache and sends a delegation query if
//necessary
func handleMissingKeys(sectionSender sectionWithSigSender, missingKeys map[rainslib.SignatureMetaData]bool) {
	section := sectionSender.Section
	log.Info("Some public keys are missing. Add section to pending signature cache",
		"#missingKeys", len(missingKeys), "section", section)
	for k := range missingKeys {
		if sendQuery := pendingKeys.Add(sectionSender, k.Algorithm, k.KeyPhase); sendQuery {
			token := rainslib.GenerateToken()
			exp := getQueryValidity(section.Sigs(rainslib.RainsKeySpace))
			if ok := pendingKeys.AddToken(token, exp, sectionSender.Sender,
				section.GetSubjectZone(), section.GetContext()); ok {
				msg := rainslib.NewQueryMessage(section.GetSubjectZone(), section.GetContext(),
					exp, []rainslib.ObjectType{rainslib.OTDelegation}, nil, token)
				SendMessage(msg, getRootAddr())
				continue
			}
		}
		log.Info("Already issued a delegation query for this context and zone.",
			"zone", section.GetSubjectZone(), "context", section.GetContext())
	}
}

//getQueryValidity returns the expiration value for a delegation query.
//It is either a configured upper bound or if smaller the longest validity time of all present signatures.
func getQueryValidity(sigs []rainslib.Signature) (validity int64) {
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

//validSignature validates section's signatures and strips all expired signatures away.
//Returns false if there are no signatures left (not considering internal sections) or if at least one signature is invalid (due to incorrect signature)
func validSignature(section rainslib.MessageSectionWithSig, keys map[rainslib.PublicKeyID][]rainslib.PublicKey) bool {
	switch section := section.(type) {
	case *rainslib.AssertionSection, *rainslib.AddressAssertionSection:
		return validateSignatures(section, keys)
	case *rainslib.ShardSection:
		return validShardSignatures(section, keys)
	case *rainslib.ZoneSection:
		return validZoneSignatures(section, keys)
	case *rainslib.AddressZoneSection:
		return validAddressZoneSignatures(section, keys)
	default:
		log.Warn("Not supported Msg Section")
		return false
	}
}

//validShardSignatures validates all signatures on the shard and contained in the shard's content
//It returns false if there is a signatures that does not verify
//It removes the context and subjectZone of all contained assertions (which was necessary for signature verification)
func validShardSignatures(section *rainslib.ShardSection, keys map[rainslib.PublicKeyID][]rainslib.PublicKey) bool {
	if !validateSignatures(section, keys) || !validContainedAssertions(section.Content, keys) {
		return false
	}
	return true
}

//validZoneSignatures validates all signatures on the zone and contained assertions and shards
//It returns false if there is a signatures that does not verify
//It removes the context and subjectZone of all contained assertions and shards (which was necessary for signature verification)
func validZoneSignatures(section *rainslib.ZoneSection, keys map[rainslib.PublicKeyID][]rainslib.PublicKey) bool {
	if !validateSignatures(section, keys) {
		return false
	}
	for _, sec := range section.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection:
			if !validContainedAssertions([]*rainslib.AssertionSection{sec}, keys) {
				return false
			}
		case *rainslib.ShardSection:
			if !rainsSiglib.CheckSectionSignatures(sec, keys, sigEncoder, Config.MaxCacheValidity) ||
				!validContainedAssertions(sec.Content, keys) {
				return false
			}
			sec.Context = ""
			sec.SubjectZone = ""
		default:
			log.Warn("Unknown message section", "messageSection", section)
			return false
		}
	}
	return true
}

//validContainedAssertions validates all signatures on the contained assertions
//It returns false if there is a signatures that does not verify
//It removes the context and subjectZone of all contained assertions (which was necessary for signature verification)
func validContainedAssertions(assertions []*rainslib.AssertionSection, keys map[rainslib.PublicKeyID][]rainslib.PublicKey) bool {
	for _, assertion := range assertions {
		if !rainsSiglib.CheckSectionSignatures(assertion, keys, sigEncoder, Config.MaxCacheValidity) {
			return false
		}
		assertion.Context = ""
		assertion.SubjectZone = ""
	}
	return true
}

//validAddressZoneSignatures validates all signatures on the address zone and contained addressAssertions
//It returns false if there is a signatures that does not verify
//It removes the context of all contained addressAssertions (which was necessary for signature verification)
func validAddressZoneSignatures(section *rainslib.AddressZoneSection, keys map[rainslib.PublicKeyID][]rainslib.PublicKey) bool {
	if !validateSignatures(section, keys) {
		return false
	}
	for _, assertion := range section.Content {
		if !rainsSiglib.CheckSectionSignatures(assertion, keys, sigEncoder, Config.MaxCacheValidity) {
			return false
		}
		assertion.Context = ""
	}
	return true
}

//validateSignatures returns true if all non expired signatures of section are valid and there is at least one signature valid before Config.MaxValidity.
//It removes valid signatures that are expired
func validateSignatures(section rainslib.MessageSectionWithSig, keys map[rainslib.PublicKeyID][]rainslib.PublicKey) bool {
	if !rainsSiglib.CheckSectionSignatures(section, keys, sigEncoder, Config.MaxCacheValidity) {
		return false //already logged
	}
	if section.ValidSince() == math.MaxInt64 {
		log.Warn("No signature is valid before the MaxValidity date in the future.")
		return false
	}
	return len(section.Sigs(rainslib.RainsKeySpace)) > 0
}
