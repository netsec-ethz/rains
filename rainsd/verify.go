package rainsd

import (
	"fmt"
	"math/rand"
	"rains/rainslib"
	"strconv"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//zoneKeys contains a set of zone public keys
//key: PendingSignatureCacheKey value:PublicKey
var zoneKeys Cache

//pendingSignatures contains a mapping from all self issued pending queries to the set of message bodies waiting for it together with a timeout.
//key: PendingSignatureCacheKey value: *PendingSignatureCacheValue
//TODO make the value thread safe. Store a list of PendingSignatureCacheValue objects which can be added and deleted
var pendingSignatures Cache

func initVerif() {
	var err error
	//init cache
	zoneKeys = &LRUCache{}
	err = zoneKeys.New(int(Config.ZoneKeyCacheSize))
	if err != nil {
		log.Error("Cannot create zoneKeyCache", "error", err)
		panic(err)
	}
	//TODO CFE to remove, here for testing purposes
	pubKey, _, _ := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	zoneKeys.Add(PendingSignatureCacheKey{KeySpace: "0", Context: ".", SubjectZone: ".ch"}, rainslib.PublicKey{Key: pubKey, Type: rainslib.Ed25519, ValidUntil: 1690086564})
	pendingSignatures = &LRUCache{}
	err = pendingSignatures.New(int(Config.PendingSignatureCacheSize))
	if err != nil {
		log.Error("Cannot create pendingSignatureCache", "error", err)
		panic(err)
	}
}

//Verify verifies the incoming message section. It sends a notification if the msg section is inconsistent and it validates the signatures, stripping of invalid once.
//If no signature remain on an assertion, shard or zone then the corresponding msg section gets removed.
func Verify(msgSender MsgSectionSender) {
	log.Info("Verify Message Section", "MsgSection", msgSender.Msg)
	switch section := msgSender.Msg.(type) {
	case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection:
		if !containedAssertionsAndShardsValid(msgSender) {
			return
		}
		if VerifySignatures(section.(rainslib.MessageSectionWithSig), msgSender.Sender, false, nil) {
			Assert(section.(rainslib.MessageSectionWithSig))
		} else {
			log.Warn(fmt.Sprintf("Pending or dropped %T (due to validation failure)", section), "MsgSectionWithSig", section)
		}
	case *rainslib.QuerySection:
		if validQuery(section, msgSender.Sender) {
			Query(section)
		}
	default:
		log.Warn("Not supported Msg section to verify", "MsgSection", section)
	}
}

//validQuery validates the expiration time of the query
func validQuery(section *rainslib.QuerySection, sender ConnInfo) bool {
	if int64(section.Expires) < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", section.Expires)
		return false
	}
	log.Info("Query is valid", "QuerySection", section)
	return true
}

//containedAssertionsAndShardsValid compares the context and the subject zone of the outer message section with the contained message bodies.
//If they differ, an inconsistency notification msg is sent to the sender and false is returned
func containedAssertionsAndShardsValid(msgSender MsgSectionSender) bool {
	switch msg := msgSender.Msg.(type) {
	case *rainslib.AssertionSection:
		return true
	case *rainslib.ShardSection:
		for _, assertion := range msg.Content {
			if !containedSectionValid(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
				return false
			}
		}
	case *rainslib.ZoneSection:
		for _, section := range msg.Content {
			switch section := section.(type) {
			case *rainslib.AssertionSection:
				if !containedSectionValid(section, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
					return false
				}
			case *rainslib.ShardSection:
				if !containedSectionValid(section, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
					return false
				}
				for _, assertion := range section.Content {
					if !containedSectionValid(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
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
func containedSectionValid(section rainslib.MessageSectionWithSig, context string, subjectZone string, token rainslib.Token, sender ConnInfo) bool {
	if section.GetContext() != context || section.GetSubjectZone() != subjectZone {
		log.Warn(fmt.Sprintf("Contained %T's context or zone is inconsistent with outer section's", section),
			fmt.Sprintf("%T", section), section, "Outer context", context, "Outerzone", subjectZone)
		sendNotificationMsg(token, sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//VerifySignatures verifies all signatures and strips off invalid signatures. If the public key is missing it issues a query and put the msg section on a waiting queue and
//adds a callback to the pendingSignatures cache
//returns false if there is no signature left on the message or when some public keys are missing
//TODO CFE verify whole signature chain (do not forget to check expiration)
func VerifySignatures(section rainslib.MessageSectionWithSig, sender ConnInfo, forceValidate bool, wg *sync.WaitGroup) bool {
	keyIDs := make(map[PendingSignatureCacheKey]string)
	for _, sig := range section.Sigs() {
		if sig.KeySpace != rainslib.RainsKeySpace {
			log.Warn("Unsupported keyspace", "KeySpaceID", sig.KeySpace)
		}
		cacheKey := PendingSignatureCacheKey{KeySpace: strconv.Itoa(int(sig.KeySpace)), Context: section.GetContext(), SubjectZone: section.GetSubjectZone()}
		keyIDs[cacheKey] = strconv.Itoa(int(sig.KeySpace))
	}
	publicKeys, missingKeys, ok := publicKeysPresent(keyIDs)
	if ok || forceValidate {
		if forceValidate {
			log.Info("ForceValidate", "MsgSectionWithSig", section, "publicKeys", publicKeys)
		} else {
			log.Info("All public keys are present.", "MsgSectionWithSig", section)
		}
		return validSignature(section, publicKeys)
	}
	log.Info("Some public keys are missing", "#MissingKeys", len(missingKeys))
	for missingKey := range missingKeys {
		if v, ok := pendingSignatures.Get(missingKey); ok {
			v := v.(*PendingSignatureCacheValue)
			if v.ValidUntil < time.Now().Unix() && v.Retries() > 0 {
				handleMissingPublicKey(missingKey, sender, section, v)
			}
		} else {
			handleMissingPublicKey(missingKey, sender, section, nil)
		}
	}
	return false
}

//publicKeysPresent returns true if all public keys are in the cache together with a map of keys and missingKeys
func publicKeysPresent(keyIDs map[PendingSignatureCacheKey]string) (map[string]rainslib.PublicKey, map[PendingSignatureCacheKey]bool, bool) {
	allKeysPresent := true
	keys := make(map[string]rainslib.PublicKey)
	missingKeys := make(map[PendingSignatureCacheKey]bool)
	for keyID, keySpace := range keyIDs {
		if key, ok := zoneKeys.Get(keyID); ok {
			if int64(key.(rainslib.PublicKey).ValidUntil) < time.Now().Unix() {
				log.Info("Key is not valid anymore")
				zoneKeys.Remove(keyID)
				allKeysPresent = false
				missingKeys[keyID] = true
			} else {
				log.Info("Corresponding Public key in cash.", "CacheKey", keyID, "PublicKey", key)
				if key, ok := key.(rainslib.PublicKey); ok {
					keys[keySpace] = key
				} else {
					allKeysPresent = false
					missingKeys[keyID] = true
					log.Warn("Value in zoneKeyCache is not a public key", "Value", key)
				}
			}
		} else {
			log.Info("Public key not in zoneKeyCache", "CacheKey", keyID)
			allKeysPresent = false
			missingKeys[keyID] = true
		}
	}
	return keys, missingKeys, allKeysPresent
}

//handleMissingPublicKey adds or updates the current msg section to pendingSignatures and sends a delegation query for the missing key
func handleMissingPublicKey(cacheKey PendingSignatureCacheKey, sender ConnInfo, section rainslib.MessageSectionWithSig, value *PendingSignatureCacheValue) {
	//TODO CFE How large should we set the expiration time of the query
	expTime := time.Now().Unix() + 1000
	if value != nil {
		value.MsgSectionList.Add(section)
		value.DecRetries()
	} else {
		//TODO CFE add number of retries to ServerConfig
		list := MsgSectionWithSigList{MsgSectionWithSigList: []rainslib.MessageSectionWithSig{section}}
		if !pendingSignatures.Add(cacheKey, PendingSignatureCacheValue{ValidUntil: expTime, retries: 1, MsgSectionList: list}) {
			//Was not able to add msgSection to pendingqueue, retry
			if v, ok := pendingSignatures.Get(cacheKey); ok {
				if v, ok := v.(PendingSignatureCacheValue); ok {
					handleMissingPublicKey(cacheKey, sender, section, &v)
					return
				}
			}
			log.Error("Cannot add callback for msgSection", "MsgSection", section)
			return
		}
	}
	sendDelegationQuery(cacheKey, expTime, sender)
}

//sendDelegationQuery sendes a delegation query back to the sender of the MsgSectionWithSig
func sendDelegationQuery(cacheKey PendingSignatureCacheKey, expTime int64, sender ConnInfo) {
	token := GenerateToken()
	querySection := rainslib.QuerySection{Context: cacheKey.Context, SubjectName: cacheKey.SubjectZone, Expires: int(expTime), Token: token, Types: rainslib.Delegation}
	query := rainslib.RainsMessage{Token: GenerateToken(), Content: []rainslib.MessageSection{&querySection}}
	msg, err := msgParser.ParseRainsMsg(query)
	if err != nil {
		log.Warn("Cannot parse a delegation Query", "Query", query)
	}
	log.Info("Send delegation Query", "Query", querySection)
	addToActiveTokenCache(string(token))
	//TODO CFE is the sender correctly chosen?
	SendTo(msg, sender)
}

//validSignature validates the signatures on a MessageSectionWithSig and strips all signatures away that are not valid.
//Returns false If there are no signatures left
func validSignature(section rainslib.MessageSectionWithSig, keys map[string]rainslib.PublicKey) bool {
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
func validShardSignatures(section *rainslib.ShardSection, keys map[string]rainslib.PublicKey) bool {
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
func validZoneSignatures(section *rainslib.ZoneSection, keys map[string]rainslib.PublicKey) bool {
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

//validateSignatures returns true if all signatures of the section are valid
func validateSignatures(section rainslib.MessageSectionWithSig, keys map[string]rainslib.PublicKey) bool {
	log.Info(fmt.Sprintf("Validate %T", section), "MsgSection", section)
	if len(section.Sigs()) == 0 {
		log.Warn("Section does not contain any signature")
		return false
	}
	stub := section.CreateStub()
	bareStub, _ := msgParser.RevParseSignedMsgSection(stub)
	for _, sig := range section.Sigs() {
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Warn("signature expired", "expTime", sig.ValidUntil)
			return false
		} else if !VerifySignature(sig.Algorithm, keys[strconv.Itoa(int(sig.KeySpace))].Key, []byte(bareStub), sig.Data) {
			log.Warn("signatures do not match")
			return false
		}
	}
	return true
}

//Delegate adds the given public key to the zoneKeyCache
func Delegate(context string, subjectZone string, cipherType rainslib.SignatureAlgorithmType, keySpace rainslib.KeySpaceID, key []byte, until uint) {
	pubKey := rainslib.PublicKey{Type: cipherType, Key: key, ValidUntil: until}
	ks := strconv.Itoa(int(keySpace))
	zoneKeys.Add(PendingSignatureCacheKey{KeySpace: ks, Context: context, SubjectZone: subjectZone}, pubKey)
}

func workPendingSignatures() {
	for {
		//TODO CFE add to config?
		time.Sleep(time.Second)
		keys := pendingSignatures.Keys()
		var wg sync.WaitGroup
		for _, key := range keys {
			if v, ok := pendingSignatures.Get(key); ok {
				if v, ok := v.(PendingSignatureCacheValue); ok {
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
}

func handleExpiredPendingSignatures(section rainslib.MessageSectionWithSig, wg *sync.WaitGroup) {
	defer wg.Done()
	if VerifySignatures(section, ConnInfo{}, true, wg) {
		Assert(section)
	}
}
