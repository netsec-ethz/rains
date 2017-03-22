package rainsd

import (
	"rains/rainslib"
	"strconv"
	"sync"
	"time"

	"bytes"

	"fmt"

	log "github.com/inconshreveable/log15"
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
	zoneKeys.Add(PendingSignatureCacheKey{KeySpace: "0", Context: ".", SubjectZone: ".ch"}, rainslib.PublicKey{Key: []byte("Test"), Type: rainslib.Sha256, ValidUntil: 1690086564})
	pendingSignatures = &LRUCache{}
	err = pendingSignatures.New(int(Config.PendingSignatureCacheSize))
	if err != nil {
		log.Error("Cannot create pendingSignatureCache", "error", err)
		panic(err)
	}
}

//Verify verifies the incoming message body. It sends a notification if the msg body is inconsistent and it validates the signatures, stripping of invalid once.
//If no signature remain on an assertion, shard or zone then the corresponding msg body gets removed.
func Verify(msgSender MsgBodySender) {
	log.Info("Verify Message Body", "MsgBody", msgSender.Msg)
	switch body := msgSender.Msg.(type) {
	case *rainslib.AssertionBody:
		if VerifySignature(body, msgSender.Sender, false, nil) {
			AssertA(body)
		} else {
			log.Warn("Pending or dropped Assertion (due to validation failure)", "Assertion", *body)
		}
	case *rainslib.ShardBody:
		if !containedAssertionsAndShardsValid(msgSender) {
			return
		}
		if VerifySignature(body, msgSender.Sender, false, nil) {
			AssertS(body)
		} else {
			log.Warn("Pending or dropped Shard (due to validation failure)", "Shard", *body)
		}
	case *rainslib.ZoneBody:
		if !containedAssertionsAndShardsValid(msgSender) {
			return
		}
		if VerifySignature(body, msgSender.Sender, false, nil) {
			AssertZ(body)
		} else {
			log.Warn("Pending or dropped Zone (due to validation failure)", "Zone", *body)
		}
	case *rainslib.QueryBody:
		if validQuery(body, msgSender.Sender) {
			Query(body)
		}
	default:
		log.Warn("Not supported Msg body to verify", "MsgBody", body)
	}
}

//validQuery validates the expiration time of the query
func validQuery(body *rainslib.QueryBody, sender ConnInfo) bool {
	if int64(body.Expires) < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", body.Expires)
		return false
	}
	log.Info("Query is valid", "QueryBody", body)
	return true
}

//containedAssertionsAndShardsValid compares the context and the subject zone of the outer message body with the contained message bodies.
//If they differ, an inconsistency notification msg is sent to the sender and false is returned
func containedAssertionsAndShardsValid(msgSender MsgBodySender) bool {
	switch msg := msgSender.Msg.(type) {
	case *rainslib.ShardBody:
		for _, assertion := range msg.Content {
			if !containedBodyValid(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
				return false
			}
		}
	case *rainslib.ZoneBody:
		for _, body := range msg.Content {
			switch body := body.(type) {
			case *rainslib.AssertionBody:
				if !containedBodyValid(body, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
					return false
				}
			case *rainslib.ShardBody:
				if !containedBodyValid(body, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
					return false
				}
				for _, assertion := range body.Content {
					if !containedBodyValid(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
						return false
					}
				}
			default:
				log.Warn("Unknown Body contained in zone", "msgBody", body)
				sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
				return false
			}
		}
	default:
		log.Warn("Message Body is not a Shard nor a Zone Body", "body", msg)
		sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//containedBodyValid checks if a contained body's context and subject zone is equal to the parameters.
//If not a inconsistency notification message is sent to the sender and false is returned
func containedBodyValid(body rainslib.MessageBodyWithSig, context string, subjectZone string, token rainslib.Token, sender ConnInfo) bool {
	if body.GetContext() != context || body.GetSubjectZone() != subjectZone {
		log.Warn(fmt.Sprintf("Contained %T's context or zone is inconsistent with outer body's", body),
			fmt.Sprintf("%T", body), body, "Outer context", context, "Outerzone", subjectZone)
		sendNotificationMsg(token, sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//VerifySignature verifies all signatures and strips off invalid signatures. If the public key is missing it issues a query and put the msg body on a waiting queue and
//adds a callback to the pendingSignatures cache
//returns false if there is no signature left on the message or when some public keys are missing
//TODO CFE verify whole signature chain (do not forget to check expiration)
func VerifySignature(body rainslib.MessageBodyWithSig, sender ConnInfo, forceValidate bool, wg *sync.WaitGroup) bool {
	keyIDs := make(map[PendingSignatureCacheKey]string)
	for _, sig := range body.Sigs() {
		if sig.KeySpace != rainslib.RainsKeySpace {
			log.Warn("Unsupported keyspace", "KeySpaceID", sig.KeySpace)
		}
		cacheKey := PendingSignatureCacheKey{KeySpace: strconv.Itoa(int(sig.KeySpace)), Context: body.GetContext(), SubjectZone: body.GetSubjectZone()}
		keyIDs[cacheKey] = strconv.Itoa(int(sig.KeySpace))
	}
	publicKeys, missingKeys, ok := publicKeysPresent(keyIDs)
	if ok || forceValidate {
		if forceValidate {
			log.Info("ForceValidate", "MsgBodyWithSig", body, "publicKeys", publicKeys)
		} else {
			log.Info("All public keys are present.", "MsgBodyWithSig", body)
		}
		return validSignature(body, publicKeys)
	}
	log.Info("Some public keys are missing", "#MissingKeys", len(missingKeys))
	for missingKey := range missingKeys {
		if v, ok := pendingSignatures.Get(missingKey); ok {
			v := v.(*PendingSignatureCacheValue)
			if v.ValidUntil < time.Now().Unix() && v.Retries() > 0 {
				handleMissingPublicKey(missingKey, sender, body, v)
			}
		} else {
			handleMissingPublicKey(missingKey, sender, body, nil)
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

//handleMissingPublicKey adds or updates the current msg body to pendingSignatures and sends a delegation query for the missing key
func handleMissingPublicKey(cacheKey PendingSignatureCacheKey, sender ConnInfo, body rainslib.MessageBodyWithSig, value *PendingSignatureCacheValue) {
	//TODO CFE How large should we set the expiration time of the query
	expTime := time.Now().Unix() + 1000
	if value != nil {
		value.MsgBodyList.Add(body)
		value.DecRetries()
	} else {
		//TODO CFE add number of retries to ServerConfig
		list := MsgBodyWithSigList{MsgBodyWithSigList: []rainslib.MessageBodyWithSig{body}}
		if !pendingSignatures.Add(cacheKey, PendingSignatureCacheValue{ValidUntil: expTime, retries: 1, MsgBodyList: list}) {
			//Was not able to add msgBody to pendingqueue, retry
			if v, ok := pendingSignatures.Get(cacheKey); ok {
				if v, ok := v.(PendingSignatureCacheValue); ok {
					handleMissingPublicKey(cacheKey, sender, body, &v)
					return
				}
			}
			log.Error("verify.handleMissingPublicKey(): Cannot add callback for msgBody", "MsgBody", body)
			return
		}
	}
	sendDelegationQuery(cacheKey, expTime, sender)
}

//sendDelegationQuery sendes a delegation query back to the sender of the MsgBodyWithSig
func sendDelegationQuery(cacheKey PendingSignatureCacheKey, expTime int64, sender ConnInfo) {
	token := GenerateToken()
	queryBody := rainslib.QueryBody{Context: cacheKey.Context, SubjectName: cacheKey.SubjectZone, Expires: int(expTime), Token: token, Types: rainslib.Delegation}
	query := rainslib.RainsMessage{Token: GenerateToken(), Content: []rainslib.MessageBody{&queryBody}}
	msg, err := msgParser.ParseRainsMsg(query)
	if err != nil {
		log.Warn("Cannot parse a delegation Query", "Query", query)
	}
	log.Info("Send delegation Query", "Query", queryBody)
	//TODO CFE is the sender correctly chosen?
	SendTo(msg, sender)
}

//validSignature validates the signatures on a MessageBodyWithSig and strips all signatures away that are not valid.
//Returns false If there are no signatures left
func validSignature(body rainslib.MessageBodyWithSig, keys map[string]rainslib.PublicKey) bool {
	switch body := body.(type) {
	case *rainslib.AssertionBody:
		return validAssertionSignatures(body, keys)
	case *rainslib.ShardBody:
		return validShardSignature(body, keys)
	case *rainslib.ZoneBody:
		//TODO CFE implement this case
		log.Warn("Not yet supported CFE")
	default:
		log.Warn("Verify.validSignature(): Not supported Msg Body")
	}
	return false
}

//validAssertionSignatures validates the signatures on an assertion body and strips all signatures away that are not valid.
//It returns false if there are no signatures left
func validAssertionSignatures(body *rainslib.AssertionBody, keys map[string]rainslib.PublicKey) bool {
	assertionStub := &rainslib.AssertionBody{}
	*assertionStub = *body
	return validateSignature(assertionStub, body, keys)
}

//validShardSignature validates all signatures on and contained in a shard body and strips all signatures away that are not valid.
//It returns false if there are no signatures left
func validShardSignature(body *rainslib.ShardBody, keys map[string]rainslib.PublicKey) bool {
	//TODO CFE FIXME deep copy elements
	shardStub := &rainslib.ShardBody{}
	*shardStub = *body
	hasSig := validateSignature(shardStub, body, keys)
	for i, assertion := range body.Content {
		assertionStub := &rainslib.AssertionBody{}
		*assertionStub = *assertion
		if !validateSignature(assertionStub, assertion, keys) {
			body.Content = append(body.Content[:i], body.Content[:i+1]...)
		}
	}
	//if shard has no valid sig, still use valid assertions
	if !hasSig {
		for _, assertion := range body.Content {
			AssertA(assertion)
		}
	}
	return hasSig
}

func validateSignature(stub, body rainslib.MessageBodyWithSig, keys map[string]rainslib.PublicKey) bool {
	log.Info(fmt.Sprintf("Validate %T", body), "MsgBody", body)
	stub.DeleteAllSigs()
	bareStub, _ := msgParser.RevParseSignedMsgBody(stub)
	for i, sig := range body.Sigs() {
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Warn("signature expired", "expTime", sig.ValidUntil)
			body.DeleteSig(i)
		} else if newSig := GenerateHMAC([]byte(bareStub), sig.Algorithm, keys[strconv.Itoa(int(sig.KeySpace))].Key)[len(bareStub):]; !bytes.Equal(newSig, sig.Data) {
			log.Warn("signatures do not match", "signature", sig.Data, "calculatedSig", newSig)
			body.DeleteSig(i)
		}
	}
	return len(body.Sigs()) > 0
}

//Delegate adds the given public key to the zoneKeyCache
func Delegate(context string, subjectZone string, cipherType rainslib.AlgorithmType, keySpace rainslib.KeySpaceID, key []byte, until uint) {
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
						list := v.MsgBodyList.GetListAndClose()
						pendingSignatures.Remove(key)
						for _, body := range list {
							wg.Add(1)
							go handleExpiredPendingSignatures(body, &wg)
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

func handleExpiredPendingSignatures(body rainslib.MessageBodyWithSig, wg *sync.WaitGroup) {
	defer wg.Done()
	if VerifySignature(body, ConnInfo{}, true, wg) {
		switch body := body.(type) {
		case *rainslib.AssertionBody:
			AssertA(body)
		case *rainslib.ShardBody:
			AssertS(body)
		case *rainslib.ZoneBody:
			AssertZ(body)
		default:
			log.Warn("verify.handleExpiredPendingSignatures(): Not supported Message Body with Signature", "MsgBody", body)
		}
	}
}
