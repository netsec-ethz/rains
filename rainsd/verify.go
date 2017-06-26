package rainsd

import (
	"fmt"
	"math"
	"net"
	"rains/rainsSiglib"
	"rains/rainslib"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
)

//zoneKeyCache contains a set of zone public keys
var zoneKeyCache keyCache

//infrastructureKeyCache contains a set of infrastructure public keys
var infrastructureKeyCache keyCache

//externalKeyCache contains a set of external public keys
var externalKeyCache keyCache

//pendingSignatures contains all sections that are waiting for a delegation query to arrive such that their signatures can be verified.
var pendingSignatures pendingSignatureCache

var sigEncoder rainslib.SignatureFormatEncoder

//initVerify initialized the module which is responsible for checking the validity of the signatures and the structure of the sections.
//It spawns a goroutine which periodically goes through the cache and removes outdated entries, see reapVerify()
func initVerify() error {
	//init cache
	var err error
	zoneKeyCache, err = createKeyCache(int(Config.ZoneKeyCacheSize))
	if err != nil {
		log.Error("Cannot create zone key Cache", "error", err)
		return err
	}
	if err := loadRootZonePublicKey(); err != nil {
		return err
	}

	infrastructureKeyCache, err = createKeyCache(int(Config.InfrastructureKeyCacheSize))
	if err != nil {
		log.Error("Cannot create infrastructure key cache", "error", err)
		return err
	}

	externalKeyCache, err = createKeyCache(int(Config.ExternalKeyCacheSize))
	if err != nil {
		log.Error("Cannot create external key cache", "error", err)
		return err
	}

	pendingSignatures, err = createPendingSignatureCache(int(Config.PendingSignatureCacheSize))
	if err != nil {
		log.Error("Cannot create pending signature cache", "error", err)
		return err
	}

	go reapVerify()
	return nil
}

//verify verifies msgSender.Section
//It checks the consistency of the msgSender.Section and if it is inconsistent a notification msg is sent. (Consistency with cached elements is checked later in engine)
//It validates all signatures (including contained once), stripping of expired once.
//If no signature remains on an assertion, shard, zone, addressAssertion or addressZone it gets dropped (signatures of contained sections are not taken into account).
//If there happens an error in the signature verification process of any signature, the whole section gets dropped (signatures of contained sections are also considered)
func verify(msgSender msgSectionSender) {
	log.Info(fmt.Sprintf("Verify %T", msgSender.Section), "msgSection", msgSender.Section)
	switch section := msgSender.Section.(type) {
	case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection:
		sectionSender := sectionWithSigSender{Section: section.(rainslib.MessageSectionWithSig), Sender: msgSender.Sender, Token: msgSender.Token}
		if containedSectionsInvalid(sectionSender) {
			return //already logged, that contained section is invalid
		}
		if contextInvalid(sectionSender.Section.GetContext()) {
			sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.RcvInconsistentMsg)
			return //already logged, that context is invalid
		}
		if zone, ok := section.(*rainslib.ZoneSection); ok && !containedShardsAreConsistent(zone) {
			return //already logged, that the zone is internally invalid
		}
		if verifySignatures(sectionSender) {
			assert(sectionSender, authoritative[contextAndZone{Context: sectionSender.Section.GetContext(), Zone: sectionSender.Section.GetSubjectZone()}])
		}
	case *rainslib.AddressAssertionSection, *rainslib.AddressZoneSection:
		sectionSender := sectionWithSigSender{Section: section.(rainslib.MessageSectionWithSig), Sender: msgSender.Sender, Token: msgSender.Token}
		if containedSectionsInvalid(sectionSender) {
			return //already logged, that contained section is invalid
		}
		if contextInvalid(sectionSender.Section.GetContext()) {
			sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.RcvInconsistentMsg)
			return //already logged, that context is invalid
		}
		if verifySignatures(sectionSender) {
			assert(sectionSender, authoritative[contextAndZone{Context: sectionSender.Section.GetContext(), Zone: sectionSender.Section.GetSubjectZone()}])
		}
	case *rainslib.AddressQuerySection:
		if contextInvalid(section.Context) {
			sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
			return //already logged, that context is invalid
		}
		if validQuery(section.Expires) {
			addressQuery(section, msgSender.Sender)
		}
	case *rainslib.QuerySection:
		if contextInvalid(section.Context) {
			sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
			return //already logged, that context is invalid
		}
		if validQuery(section.Expires) {
			query(section, msgSender.Sender)
		}
	default:
		log.Warn("Not supported Msg section to verify", "msgSection", section)
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

//validQuery returns false when the expires is in the past
func validQuery(expires int64) bool {
	if expires < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", expires)
		return false
	}
	log.Info("Query is valid")
	return true
}

//containedSectionsInvalid returns
//For assertions: false
//For addressAssertions: true if it contains invalid object types
//For shards and zones: true if any of the contained sections' context or subjectZone is not the empty string
//OR any contained assertion's subjectName is outside the range of its outer shard (the shard that contains the assertion)
//For addressZones: true if any of the contained addressAssertions' context is not the empty string
//OR any contained addressAssertion's subjectAddress is not within the zone's subjectAddress or contains invalid object types
//Additionally for zones: true if the contained sections are not of type assertion or shard. This case should never happen
func containedSectionsInvalid(sectionSender sectionWithSigSender) bool {
	switch sec := sectionSender.Section.(type) {
	case *rainslib.AssertionSection:
		return false //assertions do not contain sections
	case *rainslib.AddressAssertionSection:
		if addressAssertionInvalidObjectType(sec) {
			return true
		}
	case *rainslib.ShardSection:
		for _, assertion := range sec.Content {
			if sectionHasContextOrSubjectZone(assertion) || !containedSectionInRange(assertion.SubjectName, sec, sectionSender) {
				return true
			}
		}
	case *rainslib.ZoneSection:
		for _, section := range sec.Content {
			//check that all contained assertions and shards of this zone have the same context and subjectZone as the zone
			switch section := section.(type) {
			case *rainslib.AssertionSection:
				if sectionHasContextOrSubjectZone(section) {
					return true
				}
			case *rainslib.ShardSection:
				if sectionHasContextOrSubjectZone(section) {
					return true
				}
				for _, assertion := range section.Content {
					if sectionHasContextOrSubjectZone(assertion) || !containedSectionInRange(assertion.SubjectName, section, sectionSender) {
						return true
					}
				}
			default:
				log.Error("Contained section is not an assertion or a shard", "containedSectionType", fmt.Sprintf("%T", section))
				return true
			}
		}
	case *rainslib.AddressZoneSection:
		for _, addressAssertion := range sec.Content {
			if addressAssertion.Context != "" || !assertionAddrWithinZoneAddr(addressAssertion.SubjectAddr, sec.SubjectAddr) ||
				addressAssertionInvalidObjectType(addressAssertion) {
				return true
			}
		}
	default:
		log.Error("Unsupported section to check for validity", "sectionType", fmt.Sprintf("%T", sec))
		return true
	}
	return false
}

//sectionHasContextOrSubjectZone returns false if the section's context and subjectZone both are the empty string
func sectionHasContextOrSubjectZone(section rainslib.MessageSectionWithSig) bool {
	if section.GetContext() != "" || section.GetSubjectZone() != "" {
		log.Warn("Contained section has a context or subjectZone != \"\"", "section", section)
		return true
	}
	return false
}

//containedSectionInRange returns true if the assertion' subjectName is inside the shard's range.
//Otherwise it sends a inconsistency notification and returns false.
func containedSectionInRange(subjectName string, shard *rainslib.ShardSection, sectionSender sectionWithSigSender) bool {
	if shard.RangeFrom != "" && subjectName < shard.RangeFrom || shard.RangeTo != "" && subjectName > shard.RangeTo {
		log.Warn("Contained assertion's subjectName is outside the shard's range", "subjectName", subjectName,
			"Range", fmt.Sprintf("[%s:%s]", shard.RangeFrom, shard.RangeTo))
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//assertionAddrWithinZoneAddr returns true if the assertion's subjectAddress is within the outer zone's subjectAddress
func assertionAddrWithinZoneAddr(assertionSubjectAddr, zoneSubejectAddr *net.IPNet) bool {
	zprefix, _ := zoneSubejectAddr.Mask.Size()
	aprefix, _ := assertionSubjectAddr.Mask.Size()
	if aprefix < zprefix {
		log.Warn("Assertion is less specific than zone", "assertion prefix", aprefix, "zone prefix", zprefix)
		return false
	}
	if !zoneSubejectAddr.Contains(assertionSubjectAddr.IP) {
		log.Warn("Assertion network is not contained in zone network", "assertion network", assertionSubjectAddr, "zone network", zoneSubejectAddr)
		return false
	}
	return true
}

//addressAssertionInvalidObjectType returns true if the addressAssertion contains a not allowed object type
func addressAssertionInvalidObjectType(a *rainslib.AddressAssertionSection) bool {
	for _, o := range a.Content {
		if invalidObjectType(a.SubjectAddr, o.Type) {
			log.Warn("Not Allowed object type of contained address assertion.", "objectType", o.Type, "subjectAddr", a.SubjectAddr)
			return true
		}
	}
	return false
}

//invalidObjectType returns true if the object type is not allowed for the given subjectAddr.
func invalidObjectType(subjectAddr *net.IPNet, objectType rainslib.ObjectType) bool {
	prefixLength, addressLength := subjectAddr.Mask.Size()
	if addressLength == 32 {
		if prefixLength == 32 {
			return objectType != rainslib.OTName
		}
		return objectType != rainslib.OTDelegation && objectType != rainslib.OTRedirection && objectType != rainslib.OTRegistrant
	}
	if addressLength == 128 {
		if prefixLength == 128 {
			return objectType != rainslib.OTName
		}
		return objectType != rainslib.OTDelegation && objectType != rainslib.OTRedirection && objectType != rainslib.OTRegistrant
	}
	log.Warn("Invalid addressLength", "addressLength", addressLength)
	return true
}

//CFE UNTIL HERE ALREADY REFACTORED
//verifySignatures verifies all signatures and strips off expired signatures.
//If the public key is missing it issues a query and puts the section in the pendingSignatures cache.
//returns false if there is no signature left on the message or when some public keys are missing
func verifySignatures(sectionSender sectionWithSigSender) bool {
	section := sectionSender.Section
	neededKeys := neededKeys(section)
	publicKeys, missingKeys, ok := publicKeysPresent(neededKeys)
	if ok {
		log.Info("All public keys are present.", "msgSectionWithSig", section)
		return validSignature(section, publicKeys)
	}
	log.Info("Some public keys are missing", "#missingKeys", len(missingKeys))
	//Add section to the pendingSignatureCache. On arrival of a missing public key of this section, verifySignatures() will be called again on this section.
	//If several keys arrive at the same time then multiple callbacks might be called simultaneously and this section will be processed multiple times.
	//This event is expected to be rare.
	//-> FIXME CFE this cannot happen now, as we only send one query because we cannot specify the signature algorithm
	cacheValue := pendingSignatureCacheValue{sectionWSSender: sectionSender, validUntil: getQueryValidity(section.Sigs())}
	ok = pendingSignatures.Add(section.GetContext(), section.GetSubjectZone(), cacheValue)
	log.Info("Section added to the pending signature cache", "section", section)
	if ok {
		//FIXME CFE delegation query for a delegation assertion must go to a different location
		delegate := getDelegationAddress(section.GetContext(), section.GetSubjectZone())
		token := rainslib.GenerateToken()
		sendQuery(section.GetContext(), section.GetSubjectZone(), cacheValue.validUntil, rainslib.OTDelegation, token, delegate)
		activeTokens[token] = true
	} else {
		log.Info("already issued a delegation query for this context and zone.", "context", section.GetContext(), "zone", section.GetSubjectZone())
	}
	return false
}

//neededKeys returns the set of public key identifiers necessary to verify all rains signatures on the section
//it also returns assertions that contains a currently valid delegation (valid in terms of the signature's time validity)
func neededKeys(section rainslib.MessageSectionWithSig) map[keyCacheKey]bool {
	neededKeys := make(map[keyCacheKey]bool)
	switch section := section.(type) {
	case *rainslib.AssertionSection, *rainslib.AddressAssertionSection:
		extractNeededKeys(section, neededKeys)

	case *rainslib.ShardSection:
		extractNeededKeys(section, neededKeys)
		for _, a := range section.Content {
			a.Context = section.Context
			a.SubjectZone = section.SubjectZone
			extractNeededKeys(a, neededKeys)
		}
	case *rainslib.ZoneSection:
		extractNeededKeys(section, neededKeys)
		for _, sec := range section.Content {
			switch sec := sec.(type) {
			case *rainslib.AssertionSection:
				sec.Context = section.Context
				sec.SubjectZone = section.SubjectZone
				extractNeededKeys(sec, neededKeys)
			case *rainslib.ShardSection:
				sec.Context = section.Context
				sec.SubjectZone = section.SubjectZone
				extractNeededKeys(sec, neededKeys)
				for _, a := range sec.Content {
					a.Context = section.Context
					a.SubjectZone = section.SubjectZone
					extractNeededKeys(section, neededKeys)
				}
			default:
				log.Warn("Not supported message section inside zone")
			}
		}
	case *rainslib.AddressZoneSection:
		extractNeededKeys(section, neededKeys)
		for _, a := range section.Content {
			a.Context = section.Context
			extractNeededKeys(a, neededKeys)
		}
	default:
		log.Warn("Not supported message section with sig")
	}
	return neededKeys
}

//extractNeededKeys adds all key metadata to keys which are necessary to verify all section's signatures
//returns true if section is an assertion that contains a currently valid delegation
func extractNeededKeys(section rainslib.MessageSectionWithSig, keys map[keyCacheKey]bool) {
	for _, sig := range section.Sigs() {
		if sig.KeySpace != rainslib.RainsKeySpace {
			log.Debug("external keyspace", "keySpaceID", sig.KeySpace)
			continue
		}
		if assertion, ok := section.(*rainslib.AssertionSection); ok {
			containsDelegation, allElementsDelegations := analyseAssertionContent(assertion)
			if containsDelegation {
				key := keyCacheKey{
					context: assertion.Context,
					zone:    assertion.SubjectName,
					keyAlgo: rainslib.KeyAlgorithmType(sig.Algorithm),
				}
				keys[key] = true
			}
			if allElementsDelegations {
				//FIXME CFE if an assertion contains a delegation then all other elements must be delegations otherwise signature will fail.
				//add another consistency check?
				continue
			}
		}
		key := keyCacheKey{
			context: section.GetContext(),
			zone:    section.GetSubjectZone(),
			keyAlgo: rainslib.KeyAlgorithmType(sig.Algorithm),
		}
		keys[key] = true
	}
}

//analyseAssertionContent returns as a first value true if the assertion contains a delegation assertion and as a second value true if all elements are delegations.
func analyseAssertionContent(a *rainslib.AssertionSection) (bool, bool) {
	containsDelegation := false
	allElementsDelegations := true
	for _, o := range a.Content {
		if o.Type == rainslib.OTDelegation {
			containsDelegation = true
		} else {
			allElementsDelegations = false
		}
	}
	return containsDelegation, allElementsDelegations
}

//publicKeysPresent returns true if all public keys are in the cache together with a map of keys and missingKeys
func publicKeysPresent(neededKeys map[keyCacheKey]bool) (map[rainslib.KeyAlgorithmType]rainslib.PublicKey, map[keyCacheKey]bool, bool) {
	keys := make(map[rainslib.KeyAlgorithmType]rainslib.PublicKey)
	missingKeys := make(map[keyCacheKey]bool)

	for keyID := range neededKeys {
		if key, ok := zoneKeyCache.Get(keyID); ok {
			//returned public key is guaranteed to be valid
			log.Info("Corresponding Public key in cache.", "cacheKey", keyID, "publicKey", key)
			keys[keyID.keyAlgo] = key
		} else {
			log.Info("Public key not in zoneKeyCache", "cacheKey", keyID)
			missingKeys[keyID] = true
		}
	}
	return keys, missingKeys, len(missingKeys) == 0
}

//getQueryValidity returns the validUntil value for a delegation query.
//It is either a configured upper bound or if smaller the longest validity time of all present signatures.
func getQueryValidity(sigs []rainslib.Signature) int64 {
	validity := int64(0)
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

//validSignature validates the signatures on a MessageSectionWithSig and strips all expired signatures away.
//Returns false If there are no signatures left or if at least one signature is invalid (due to incorrect signature)
func validSignature(section rainslib.MessageSectionWithSig, keys map[rainslib.KeyAlgorithmType]rainslib.PublicKey) bool {
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
	}
	return false
}

//validShardSignatures validates all signatures on the shard and contained in the shard's content
//It returns false if there is a signatures that does not verify
func validShardSignatures(section *rainslib.ShardSection, keys map[rainslib.KeyAlgorithmType]rainslib.PublicKey) bool {
	if !validateSignatures(section, keys) {
		return false
	}
	for _, assertion := range section.Content {
		if !validateSignatures(assertion, keys) {
			return false
		}
		//context and subjectZone must be empty for contained assertions, but was needed for signature verification
		assertion.Context = ""
		assertion.SubjectZone = ""
	}
	return true
}

//validZoneSignatures validates all signatures on the zone and contained in a zone's conetent
//It returns false if there is a signatures that does not verify
func validZoneSignatures(section *rainslib.ZoneSection, keys map[rainslib.KeyAlgorithmType]rainslib.PublicKey) bool {
	if !validateSignatures(section, keys) {
		return false
	}
	for _, sec := range section.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection:
			if !validateSignatures(sec, keys) {
				return false
			}
			//context and subjectZone must be empty for contained assertions, but was needed for signature verification
			sec.Context = ""
			sec.SubjectZone = ""
		case *rainslib.ShardSection:
			//context and subjectZone must be empty for contained shards, but was needed for signature verification
			if !validShardSignatures(sec, keys) {
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

//validAddressZoneSignatures validates all signatures on the address zone and all contained address assertions
//It returns false if there is a signatures that does not verify
func validAddressZoneSignatures(section *rainslib.AddressZoneSection, keys map[rainslib.KeyAlgorithmType]rainslib.PublicKey) bool {
	if !validateSignatures(section, keys) {
		return false
	}
	for _, assertion := range section.Content {
		if !validateSignatures(assertion, keys) {
			return false
		}
		//context must be empty for contained addressAssertions, but was needed for signature verification
		assertion.Context = ""
	}
	return true
}

//validateSignatures returns true if all signatures of the section are valid. It removes valid signatures that are expired
func validateSignatures(section rainslib.MessageSectionWithSig, keys map[rainslib.KeyAlgorithmType]rainslib.PublicKey) bool {
	if !rainsSiglib.CheckSectionSignatures(section, keys, sigEncoder, Config.MaxCacheValidity) {
		log.Warn("signatures do not match")
		return false
	}
	if section.ValidSince() == math.MaxInt64 {
		log.Warn("No signature is valid until the MaxValidity date in the future.")
		return false
	}
	return len(section.Sigs()) > 0
}

//reapVerify deletes expired keys from the key caches and expired sections from the pendingSignature cache in intervals according to the config
func reapVerify() {
	for {
		zoneKeyCache.RemoveExpiredKeys()
		infrastructureKeyCache.RemoveExpiredKeys()
		externalKeyCache.RemoveExpiredKeys()
		pendingSignatures.RemoveExpiredSections()
		time.Sleep(Config.ReapVerifyTimeout)
	}
}
