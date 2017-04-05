package rainsd

import (
	"fmt"
	"rains/rainslib"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
)

//zoneKeyCache contains a set of zone public keys
//key: PendingSignatureCacheKey value:PublicKey
var zoneKeyCache keyCache

//infrastructureKeyCache contains a set of infrastructure public keys
var infrastructureKeyCache keyCache

//externalKeyCache contains a set of external public keys
var externalKeyCache keyCache

//pendingSignatures contains a mapping from all self issued pending queries to the set of message bodies waiting for it together with a timeout.
//key: PendingSignatureCacheKey value: *PendingSignatureCacheValue
var pendingSignatures pendingSignatureCache

func initVerify() error {
	//init cache
	/*zoneKeyCache = &LRUCache{}
	err := zoneKeyCache.New(int(Config.ZoneKeyCacheSize))
	if err != nil {
		log.Error("Cannot create zoneKeyCache", "error", err)
		return err
	}
	//TODO CFE to remove, here for testing purposes
	pubKey, _, _ := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	zoneKeyCache.Add(pendingSignatureCacheKey{KeySpace: "0", Context: ".", SubjectZone: ".ch"}, rainslib.PublicKey{Key: pubKey, Type: rainslib.Ed25519, ValidUntil: 1690086564})

	pendingSignatures = &LRUCache{}
	err = pendingSignatures.New(int(Config.PendingSignatureCacheSize))
	if err != nil {
		log.Error("Cannot create pendingSignatureCache", "error", err)
		return err
	}

	infrastructureKeyCache = &LRUCache{}
	//TODO CFE add to config
	err = infrastructureKeyCache.New(10)
	if err != nil {
		log.Error("Cannot create infrastructureKeyCache", "error", err)
		return err
	}

	externalKeyCache = &LRUCache{}
	//TODO CFE add to config
	err = externalKeyCache.New(10)
	if err != nil {
		log.Error("Cannot create externalKeyCache", "error", err)
		return err
	}*/
	return nil
}

//verify verifies the incoming message section. It sends a notification if the msg section is inconsistent and it validates the signatures, stripping of expired once.
//If no signature remain on an assertion, shard or zone then the corresponding msg section gets removed. If at least one signatures cannot be verified with the public key,
//the whole section gets dropped
func verify(msgSender msgSectionSender) {
	log.Info("Verify Message Section", "msgSection", msgSender.Msg)
	switch section := msgSender.Msg.(type) {
	case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection:
		if !containedAssertionsAndShardsValid(msgSender) {
			return //already logged, that the section is invalid
		}
		if verifySignatures(section.(rainslib.MessageSectionWithSig), msgSender.Sender, false, nil) {
			assert(section.(rainslib.MessageSectionWithSig), false)
		} else {
			log.Warn(fmt.Sprintf("Pending or dropped %T (due to validation failure)", section), "msgSectionWithSig", section)
		}
	case *rainslib.QuerySection:
		if validQuery(section, msgSender.Sender) {
			query(section)
		}
	default:
		log.Warn("Not supported Msg section to verify", "msgSection", section)
	}
}

//verifyMessageSignature verifies signatures of the message against the infrastructure key of the RAINS Server originating the message
func verifyMessageSignature(msg rainslib.RainsMessage) bool {
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
	if int64(section.Expires) < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", section.Expires)
		return false
	}
	log.Info("Query is valid", "querySection", section)
	return true
}

//containedAssertionsAndShardsValid compares the context and the subject zone of the outer message section with the contained message bodies.
//If they differ, an inconsistency notification msg is sent to the sender and false is returned
func containedAssertionsAndShardsValid(msgSender msgSectionSender) bool {
	switch msg := msgSender.Msg.(type) {
	case *rainslib.AssertionSection:
		return true //assertions do not contain sections -> always valid
	case *rainslib.ShardSection:
		//check that all contained assertions of this shard have the same context and subjectZone as the shard.
		for _, assertion := range msg.Content {
			if !containedSectionValid(assertion, msg.Context, msg.SubjectZone, msgSender) || containedSectionInRange(assertion.SubjectName, msg, msgSender) {
				return false
			}
		}
	case *rainslib.ZoneSection:
		for _, section := range msg.Content {
			//check that all contained assertions and shards of this zone have the same context and subjectZone as the zone
			switch section := section.(type) {
			case *rainslib.AssertionSection:
				if !containedSectionValid(section, msg.Context, msg.SubjectZone, msgSender) {
					return false
				}
			case *rainslib.ShardSection:
				if !containedSectionValid(section, msg.Context, msg.SubjectZone, msgSender) {
					return false
				}
				for _, assertion := range section.Content {
					if !containedSectionValid(assertion, msg.Context, msg.SubjectZone, msgSender) || containedSectionInRange(assertion.SubjectName, section, msgSender) {
						return false
					}
				}
			default:
				log.Warn("Unknown Section contained in zone", "msgSection", section)
				sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
				return false
			}
		}
	default:
		log.Warn("Message Section is not supported", "section", msg)
		sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//containedSectionValid checks if a contained section's context and subject zone is equal to the parameters.
//If not a inconsistency notification message is sent to the sender and false is returned
func containedSectionValid(section rainslib.MessageSectionWithSig, context string, subjectZone string, msgSender msgSectionSender) bool {
	if section.GetContext() != context || section.GetSubjectZone() != subjectZone {
		log.Warn(fmt.Sprintf("Contained %T's context or zone is inconsistent with outer section's", section),
			fmt.Sprintf("%T", section), section, "Outer context", context, "Outerzone", subjectZone)
		sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

func containedSectionInRange(subjectName string, shard *rainslib.ShardSection, msgSender msgSectionSender) bool {
	if shard.RangeFrom != "" && subjectName < shard.RangeFrom || shard.RangeTo != "" && subjectName > shard.RangeTo {
		log.Warn("Contained assertion's subject name is not in the shard's range", "subjectName", subjectName,
			"Range", fmt.Sprintf("[%s:%s]", shard.RangeFrom, shard.RangeTo))
		sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//verifySignatures verifies all signatures and strips off expired signatures. If the public key is missing it issues a query and put the msg section on a waiting queue and
//adds a callback to the pendingSignatures cache
//returns false if there is no signature left on the message or when some public keys are missing
//TODO CFE verify whole signature chain (do not forget to check expiration)
func verifySignatures(section rainslib.MessageSectionWithSig, sender ConnInfo, forceValidate bool, wg *sync.WaitGroup) bool {
	keyIDs := make(map[keyCacheKey]bool)
	for _, sig := range section.Sigs() {
		if sig.KeySpace != rainslib.RainsKeySpace {
			log.Warn("Unsupported keyspace", "keySpaceID", sig.KeySpace)
			continue
		}
		mapKey := keyCacheKey{
			context: section.GetContext(),
			zone:    section.GetSubjectZone(),
			keyAlgo: rainslib.KeyAlgorithmType(sig.Algorithm),
		}
		keyIDs[mapKey] = true
	}
	publicKeys, missingKeys, ok := publicKeysPresent(keyIDs)
	//FIXME CFE what is forceValidate for? -> revalidate keys if the answer of a missing public key arrived is logic correct???
	if ok || forceValidate {
		if forceValidate {
			log.Info("ForceValidate", "msgSectionWithSig", section, "publicKeys", publicKeys)
		} else {
			log.Info("All public keys are present.", "msgSectionWithSig", section)
		}
		return validSignature(section, publicKeys)
	}
	log.Info("Some public keys are missing", "#missingKeys", len(missingKeys))
	value := pendingSignatureCacheValue{
		section: section,
		//TODO CFE add expiration time of the query to server config
		ValidUntil: time.Now().Add(10 * time.Second).Unix(),
	}
	for missingKey := range missingKeys {
		//FIXME CFE is this logic correct with the add
		if ok := pendingSignatures.Add(missingKey.context, missingKey.zone, value); ok {
			//handleMissingPublicKey(missingKey, sender, section, value)
			sendDelegationQuery(missingKey, value.ValidUntil, sender)
		}
	}
	return false
}

//publicKeysPresent returns true if all public keys are in the cache together with a map of keys and missingKeys
func publicKeysPresent(keyIDs map[keyCacheKey]bool) (map[rainslib.KeyAlgorithmType]rainslib.PublicKey, map[keyCacheKey]bool, bool) {
	keys := make(map[rainslib.KeyAlgorithmType]rainslib.PublicKey)
	missingKeys := make(map[keyCacheKey]bool)
	for keyID := range keyIDs {
		if key, ok := zoneKeyCache.Get(keyID); ok {
			//returned key is guaranteed to be not expired
			log.Info("Corresponding Public key in cache.", "cacheKey", keyID, "publicKey", key)
			keys[keyID.keyAlgo] = key
		} else {
			log.Info("Public key not in zoneKeyCache", "cacheKey", keyID)
			missingKeys[keyID] = true
		}
	}
	return keys, missingKeys, len(missingKeys) == 0
}

//handleMissingPublicKey adds or updates the current section to pendingSignatures and sends a delegation query for the missing key
func handleMissingPublicKey(cacheKey keyCacheKey, sender ConnInfo, section rainslib.MessageSectionWithSig, value pendingSignatureCacheValue) {
	//FIXME CFE is this methods used???
	/*if value != nil {
		value.MsgSectionList.Add(section)
		value.DecRetries()
	} else {
		//TODO CFE add number of retries to ServerConfig
		list := msgSectionWithSigList{MsgSectionWithSigList: []rainslib.MessageSectionWithSig{section}}
		if !pendingSignatures.Add(cacheKey, pendingSignatureCacheValue{ValidUntil: expTime, retries: 1, MsgSectionList: list}) {
			//Was not able to add msgSection to pendingqueue, retry
			if v, ok := pendingSignatures.Get(cacheKey); ok {
				if v, ok := v.(pendingSignatureCacheValue); ok {
					handleMissingPublicKey(cacheKey, sender, section, &v)
					return
				}
			}
			log.Error("Cannot add callback for msgSection", "msgSection", section)
			return
		}
	}*/

}

//sendDelegationQuery sendes a delegation query back to the sender of the MsgSectionWithSig
func sendDelegationQuery(cacheKey keyCacheKey, expTime int64, sender ConnInfo) {
	token := rainslib.GenerateToken()
	querySection := rainslib.QuerySection{
		Context: cacheKey.context,
		Name:    cacheKey.zone,
		Expires: int(expTime),
		Token:   token,
		Types:   rainslib.Delegation,
	}
	query := rainslib.RainsMessage{Token: rainslib.GenerateToken(), Content: []rainslib.MessageSection{&querySection}}
	msg, err := msgParser.ParseRainsMsg(query)
	if err != nil {
		log.Warn("Cannot parse a delegation Query", "query", query)
	}
	log.Info("Send delegation Query", "query", querySection)
	activeTokens[token] = true
	//TODO CFE is the sender correctly chosen?
	sendTo(msg, sender)
}

//validSignature validates the signatures on a MessageSectionWithSig and strips all signatures away that are not valid.
//Returns false If there are no signatures left
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

//delegate adds the given public key to the zoneKeyCache
/*func delegate(context string, subjectZone string, cipherType rainslib.SignatureAlgorithmType, keySpace rainslib.KeySpaceID, key []byte, until uint) {
	pubKey := rainslib.PublicKey{Type: cipherType, Key: key, ValidUntil: until}
	ks := strconv.Itoa(int(keySpace))
	zoneKeyCache.Add(pendingSignatureCacheKey{KeySpace: ks, Context: context, SubjectZone: subjectZone}, pubKey)
}*/

/*func workPendingSignatures() {
	for {
		//TODO CFE add to config?
		time.Sleep(time.Second)
		keys := pendingSignatures.Keys()
		var wg sync.WaitGroup
		for _, key := range keys {
			if v, ok := pendingSignatures.Get(key); ok {
				if v, ok := v.(pendingSignatureCacheValue); ok {
					if v.ValidUntil < time.Now().Unix() && v.Retries() == 0 {
						list := v.MsgSectionList.GetListAndClose()
						pendingSignatures.Remove(key)
						for _, section := range list {
							wg.Add(1)
							go handleExpiredPendingSignatures(section, &wg)
						}
					}
				} else {
					log.Warn("Value of pendingSignatures is not PendingSignatureCacheValue", "value", v)
				}
			}
		}
		wg.Wait()
	}
}*/

func handleExpiredPendingSignatures(section rainslib.MessageSectionWithSig, wg *sync.WaitGroup) {
	defer wg.Done()
	if verifySignatures(section, ConnInfo{}, true, wg) {
		assert(section, false)
	}
}

func reapVerify() {
	//TODO CFE implement and create a worker that calls this function from time to time
}
