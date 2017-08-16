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

//initVerify initialized the module which is responsible for checking the validity of the signatures and the structure of the sections.
//It spawns a goroutine which periodically goes through the cache and removes outdated entries, see reapVerify()
func initVerify() error {
	err := loadRootZonePublicKey(Config.RootZonePublicKeyPath)
	if err != nil {
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
		sectionSender := sectionWithSigSender{
			Section: section.(rainslib.MessageSectionWithSig),
			Sender:  msgSender.Sender,
			Token:   msgSender.Token,
		}
		if containedSectionsInvalid(sectionSender) {
			sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
			return //already logged, that contained section is invalid
		}
		if contextInvalid(sectionSender.Section.GetContext()) {
			sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
			return //already logged, that context is invalid
		}
		if zone, ok := section.(*rainslib.ZoneSection); ok && !containedShardsAreConsistent(zone) {
			sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
			return //already logged, that the zone is internally invalid
		}
		if verifySignatures(sectionSender) {
			assert(sectionSender, authoritative[zoneContext{
				Zone:    sectionSender.Section.GetSubjectZone(),
				Context: sectionSender.Section.GetContext(),
			}])
		}
	case *rainslib.AddressAssertionSection, *rainslib.AddressZoneSection:
		sectionSender := sectionWithSigSender{
			Section: section.(rainslib.MessageSectionWithSig),
			Sender:  msgSender.Sender,
			Token:   msgSender.Token,
		}
		if containedSectionsInvalid(sectionSender) {
			sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
			return //already logged, that contained section is invalid
		}
		if contextInvalid(sectionSender.Section.GetContext()) {
			sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
			return //already logged, that context is invalid
		}
		if verifySignatures(sectionSender) {
			assert(sectionSender, authoritative[zoneContext{
				Zone:    sectionSender.Section.GetSubjectZone(),
				Context: sectionSender.Section.GetContext(),
			}])
		}
	case *rainslib.AddressQuerySection:
		if contextInvalid(section.Context) {
			sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTRcvInconsistentMsg, "")
			return //already logged, that context is invalid
		}
		if !isQueryExpired(section.Expires) {
			addressQuery(section, msgSender.Sender, msgSender.Token)
		}
	case *rainslib.QuerySection:
		if contextInvalid(section.Context) {
			sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.NTRcvInconsistentMsg, "")
			return //already logged, that context is invalid
		}
		if !isQueryExpired(section.Expires) {
			query(section, msgSender.Sender, msgSender.Token)
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

//isQueryExpired returns true if the query has expired
func isQueryExpired(expires int64) bool {
	if expires < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", expires, "now", time.Now().Unix())
		return true
	}
	log.Info("Query is not expired")
	return false
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

//containedSectionInRange returns true if the assertion's subjectName is inside the shard's range.
//Otherwise it sends a inconsistency notification and returns false.
func containedSectionInRange(subjectName string, shard *rainslib.ShardSection, sectionSender sectionWithSigSender) bool {
	if shard.RangeFrom != "" && subjectName < shard.RangeFrom || shard.RangeTo != "" && subjectName > shard.RangeTo {
		log.Warn("Contained assertion's subjectName is outside the shard's range", "subjectName", subjectName,
			"Range", fmt.Sprintf("[%s:%s]", shard.RangeFrom, shard.RangeTo))
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.NTRcvInconsistentMsg, "")
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
		for _, a := range section.Content {
			a.SubjectZone = section.GetSubjectZone()
			a.Context = section.GetContext()
		}
	case *rainslib.ZoneSection:
		for _, sec := range section.Content {
			switch sec := sec.(type) {
			case *rainslib.AssertionSection:
				sec.SubjectZone = section.GetSubjectZone()
				sec.Context = section.GetContext()
			case *rainslib.ShardSection:
				sec.SubjectZone = section.GetSubjectZone()
				sec.Context = section.GetContext()
				for _, a := range sec.Content {
					a.SubjectZone = section.GetSubjectZone()
					a.Context = section.GetContext()
				}
			default:
				log.Warn("Not supported message section inside zone")
			}
		}
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
			//TODO CFE make expiration time configurable
			exp := time.Now().Add(time.Second).Unix()
			if ok := pendingKeys.AddToken(token, exp, sectionSender.Sender,
				section.GetSubjectZone(), section.GetContext()); ok {
				msg := rainslib.NewQueryMessage(section.GetSubjectZone(), section.GetContext(),
					exp, []rainslib.ObjectType{rainslib.OTDelegation}, nil, token)
				//TODO CFE make this configurable, remove hard coding
				//SendMessage(msg, sectionSender.Sender)
				tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:5023")
				SendMessage(msg, rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr})
				continue
			}
		}
		log.Info("Already issued a delegation query for this context and zone.",
			"zone", section.GetSubjectZone(), "context", section.GetContext())
	}
}

//getQueryValidity returns the expiration value for a delegation query.
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
			if !rainsSiglib.CheckSectionSignatures(sec, keys, sigEncoder, Config.MaxCacheValidity) || !validContainedAssertions(sec.Content, keys) {
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

//reapVerify deletes expired keys from the key caches and expired sections from the pendingSignature cache in intervals according to the config
func reapVerify() {
	for {
		zoneKeyCache.RemoveExpiredKeys()
		pendingKeys.RemoveExpiredValues()
		time.Sleep(Config.ReapVerifyTimeout)
	}
}
