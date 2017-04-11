package rainsd

import (
	"fmt"
	"math/rand"
	"rains/rainslib"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

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

func initVerify() error {
	//init cache
	var err error
	zoneKeyCache, err = createKeyCache(int(Config.ZoneKeyCacheSize))
	if err != nil {
		log.Error("Cannot create zone key Cache", "error", err)
		return err
	}
	//FIXME CFE this signature is here for testing reasons, remove for production
	pubKey, _, _ := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	zoneKeyCache.Add(keyCacheKey{context: ".", zone: ".ch", keyAlgo: rainslib.KeyAlgorithmType(0)},
		rainslib.PublicKey{Key: pubKey, Type: rainslib.KeyAlgorithmType(rainslib.Ed25519), ValidUntil: 1690086564},
		false)

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
	return nil
}

//verify verifies the incoming message section. It sends a notification if the msg section is inconsistent and it validates the signatures, stripping of expired once.
//If no signature remain on an assertion, shard or zone then the corresponding msg section gets removed.
//If at least one signatures cannot be verified with the public key, the whole section gets dropped
func verify(msgSender msgSectionSender) {
	log.Info("Verify Message Section", "msgSection", msgSender.Section)
	switch section := msgSender.Section.(type) {
	case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection:
		sectionSender := sectionWithSigSender{Section: section.(rainslib.MessageSectionWithSig), Sender: msgSender.Sender, Token: msgSender.Token}
		if !containedAssertionsAndShardsValid(sectionSender) {
			return //already logged, that the section is invalid
		}
		if zone, ok := section.(*rainslib.ZoneSection); ok && !containedShardsAreConsistent(zone) {
			return //already logged, that the zone is internally invalid
		}
		if verifySignatures(sectionSender, nil) {
			assert(section.(rainslib.MessageSectionWithSig), false)
		}
	case *rainslib.QuerySection:
		if validQuery(section, msgSender.Sender) {
			query(section, msgSender.Sender)
		}
	default:
		log.Warn("Not supported Msg section to verify", "msgSection", section)
	}
}

//verifyMessageSignature verifies signatures of the message against the infrastructure key of the RAINS Server originating the message
func verifyMessageSignature(msg rainslib.RainsMessage) bool {
	log.Info("Verify Message Signature")
	if len(msg.Signatures) == 0 {
		log.Info("No signature on the message")
		return true
	}
	for _, sig := range msg.Signatures {
		//TODO CFE think about how to best implement this generically perhaps combine with assertion/shard/zone checking?
		if !validMsgSignature("", sig) {
			return false
		}
	}
	return true
}

func validMsgSignature(msgStub string, sig rainslib.Signature) bool {
	log.Warn("Not yet implemented CFE")
	return true
}

//validQuery validates the expiration time of the query
func validQuery(section *rainslib.QuerySection, sender ConnInfo) bool {
	if section.Expires < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", section.Expires)
		return false
	}
	log.Info("Query is valid", "querySection", section)
	return true
}

//containedAssertionsAndShardsValid compares the context and the subject zone of the outer section with the contained sections.
//If they differ, an inconsistency notification msg is sent to the sender and false is returned
func containedAssertionsAndShardsValid(sectionSender sectionWithSigSender) bool {
	switch sec := sectionSender.Section.(type) {
	case *rainslib.AssertionSection:
		return true //assertions do not contain sections -> always valid
	case *rainslib.ShardSection:
		//check that all contained assertions of this shard have the same context and subjectZone as the shard.
		for _, assertion := range sec.Content {
			if !containedSectionValid(assertion, sectionSender) || !containedSectionInRange(assertion.SubjectName, sec, sectionSender) {
				return false
			}
		}
	case *rainslib.ZoneSection:
		for _, section := range sec.Content {
			//check that all contained assertions and shards of this zone have the same context and subjectZone as the zone
			switch section := section.(type) {
			case *rainslib.AssertionSection:
				if !containedSectionValid(section, sectionSender) {
					return false
				}
			case *rainslib.ShardSection:
				if !containedSectionValid(section, sectionSender) {
					return false
				}
				for _, assertion := range section.Content {
					if !containedSectionValid(assertion, sectionSender) || containedSectionInRange(assertion.SubjectName, section, sectionSender) {
						return false
					}
				}
			default:
				log.Warn("Unknown Section contained in zone", "msgSection", section)
				sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.RcvInconsistentMsg)
				return false
			}
		}
	default:
		log.Warn("Message Section is not supported", "section", sec)
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//containedSectionValid checks if a contained section's context and subject zone is equal to the parameters.
//If not a inconsistency notification message is sent to the sender and false is returned
func containedSectionValid(section rainslib.MessageSectionWithSig, sectionSender sectionWithSigSender) bool {
	if section.GetContext() != sectionSender.Section.GetContext() || section.GetSubjectZone() != sectionSender.Section.GetSubjectZone() {
		log.Warn(fmt.Sprintf("Contained %T's context or zone is inconsistent with outer section's", section),
			fmt.Sprintf("%T", section), section, "Outer context", sectionSender.Section.GetContext(), "Outerzone", sectionSender.Section.GetSubjectZone())
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//containedSectionInRange returns true if the assertion is inside the shard's range.
//Otherwise it sends a inconsistency notification and returns false.
func containedSectionInRange(subjectName string, shard *rainslib.ShardSection, sectionSender sectionWithSigSender) bool {
	if shard.RangeFrom != "" && subjectName < shard.RangeFrom || shard.RangeTo != "" && subjectName > shard.RangeTo {
		log.Warn("Contained assertion's subject name is not in the shard's range", "subjectName", subjectName,
			"Range", fmt.Sprintf("[%s:%s]", shard.RangeFrom, shard.RangeTo))
		sendNotificationMsg(sectionSender.Token, sectionSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//verifySignatures verifies all signatures and strips off expired signatures.
//If the public key is missing it issues a query and puts the section in the pendingSignatures cache.
//returns false if there is no signature left on the message or when some public keys are missing
//TODO CFE verify whole signature chain (do not forget to check expiration)
func verifySignatures(sectionSender sectionWithSigSender, wg *sync.WaitGroup) bool {
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
	cacheValue := pendingSignatureCacheValue{section: section, validUntil: getQueryValidity(section.Sigs())}
	ok = pendingSignatures.Add(section.GetContext(), section.GetSubjectZone(), cacheValue)
	if ok {
		delegate := getDelegationAddress(section.GetContext(), section.GetSubjectZone())
		token := rainslib.GenerateToken()
		sendQuery(section.GetContext(), section.GetSubjectZone(), cacheValue.validUntil, rainslib.Delegation, token, delegate)
		activeTokens[token] = true
	}
	log.Info("Section added to pending signature cache", "section", section)
	return false
}

//neededKeys returns the set of public key identifiers necessary to verify all rains signatures on the section
func neededKeys(section rainslib.MessageSectionWithSig) map[keyCacheKey]bool {
	neededKeys := make(map[keyCacheKey]bool)
	for _, sig := range section.Sigs() {
		if sig.KeySpace != rainslib.RainsKeySpace {
			log.Info("external keyspace", "keySpaceID", sig.KeySpace)
			continue
		}
		mapKey := keyCacheKey{
			context: section.GetContext(),
			zone:    section.GetSubjectZone(),
			keyAlgo: rainslib.KeyAlgorithmType(sig.Algorithm),
		}
		neededKeys[mapKey] = true
	}
	return neededKeys
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
	case *rainslib.AssertionSection:
		return validateSignatures(section, keys)
	case *rainslib.ShardSection:
		return validShardSignatures(section, keys)
	case *rainslib.ZoneSection:
		return validZoneSignatures(section, keys)
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
		case *rainslib.ShardSection:
			if !validShardSignatures(sec, keys) {
				return false
			}
		default:
			log.Warn("Unknown message section", "messageSection", section)
		}
	}
	return true
}

//validateSignatures returns true if all signatures of the section are valid. It removes valid signatures that are expired
func validateSignatures(section rainslib.MessageSectionWithSig, keys map[rainslib.KeyAlgorithmType]rainslib.PublicKey) bool {
	log.Info(fmt.Sprintf("Validate %T", section), "msgSection", section)
	if len(section.Sigs()) == 0 {
		log.Warn("Section does not contain any signature")
		return false
	}
	stub := section.CreateStub()
	bareStub, _ := msgParser.RevParseSignedMsgSection(stub)
	for i, sig := range section.Sigs() {
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Warn("signature expired", "expTime", sig.ValidUntil)
			section.DeleteSig(i)
		} else if !VerifySignature(sig.Algorithm, keys[rainslib.KeyAlgorithmType(sig.Algorithm)].Key, []byte(bareStub), sig.Data) {
			log.Warn("signatures do not match")
			return false
		}
	}
	return len(section.Sigs()) > 0
}

//reapVerify deletes expired keys from the key caches and expired sections from the pendingSignature cache
func reapVerify() {
	//TODO CFE implement and create a worker that calls this function from time to time
	zoneKeyCache.RemoveExpiredKeys()
	infrastructureKeyCache.RemoveExpiredKeys()
	externalKeyCache.RemoveExpiredKeys()
	pendingSignatures.RemoveExpiredSections()
}
