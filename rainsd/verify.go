package rainsd

import (
	"rains/rainslib"
	"strconv"
	"time"

	"bytes"

	log "github.com/inconshreveable/log15"
)

//zoneKeys contains a set of zone public keys
var zoneKeys Cache

//pendingSignatures contains a mapping from all self issued pending queries to the set of messages waiting for it.
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
	//TODO CFE to remove, here fore testing purposes
	zoneKeys.Add("0..ch", rainslib.PublicKey{Key: []byte("Test"), Type: rainslib.Sha256, ValidUntil: 1690086564})
	pendingSignatures = &LRUCache{}
	err = pendingSignatures.New(int(Config.PendingSignatureCacheSize))
	if err != nil {
		log.Error("Cannot create pendingSignatureCache", "error", err)
		panic(err)
	}
}

//Verify verifies the incoming message. It sends a notification if the msg is inconsistent and it validates the signatures, stripping of invalid once. If no signature remain on
//an assertion, shard or zone then the corresponding msg body gets removed.
func Verify(msgSender MsgBodySender) {
	log.Info("Verify Message Body", "MsgBody", msgSender.Msg)
	switch body := msgSender.Msg.(type) {
	case *rainslib.AssertionBody:
		if VerifySignature(body, msgSender.Token, msgSender.Sender, nil) {
			AssertA(body)
		} else {
			log.Warn("Drop Assertion, failed verification step", "Assertion", *body)
		}
	case *rainslib.ShardBody:
		if !containedAssertionsAndShardsValid(msgSender) {
			return
		}
		VerifySignature(body, msgSender.Token, msgSender.Sender, nil)
	case *rainslib.ZoneBody:
		if !containedAssertionsAndShardsValid(msgSender) {
			return
		}
		VerifySignature(body, msgSender.Token, msgSender.Sender, nil)
	case *rainslib.QueryBody:
		if validQuery(body, msgSender.Sender) {
			Query(body)
		}
	default:
		log.Warn("Not supported Msg section body to verify", "MsgSectionBody", body)
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
//If they differ, a inconsistency notification msg is sent to the sender and false is returned
func containedAssertionsAndShardsValid(msgSender MsgBodySender) bool {
	switch msg := msgSender.Msg.(type) {
	case rainslib.ShardBody:
		for _, assertion := range msg.Content {
			if !containedAssertionValid(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
				return false
			}
		}
	case rainslib.ZoneBody:
		for _, body := range msg.Content {
			switch body := body.(type) {
			case *rainslib.AssertionBody:
				if !containedAssertionValid(body, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
					return false
				}
			case *rainslib.ShardBody:
				if body.Context != msg.Context || body.SubjectZone != msg.SubjectZone {
					log.Warn("Shard is inconsistent with Zone's context or subject zone", "ShardBody", body, "zoneBody", msg)
					sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
					return false
				}
				for _, assertion := range body.Content {
					if !containedAssertionValid(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
						return false
					}
				}
			default:
				log.Warn("Unknown Message Body contained in zone", "msgBody", body)
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

//containedAssertionValid checks if a contained shard's context and subject zone is equal to the parameters.
//If not a inconsistency notification message is sent to the sender and false is returned
func containedAssertionValid(body *rainslib.AssertionBody, context string, subjectZone string, token rainslib.Token, sender ConnInfo) bool {
	if body.Context != context || body.SubjectZone != subjectZone {
		log.Warn("Assertion is inconsistent with Shard's or zone's context or zone.", "Assertion", body, "context", context, "zone", subjectZone)
		sendNotificationMsg(token, sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//VerifySignature verifies all signatures and strips off invalid signatures. If the public key is missing it issues a query and put the msg body on waiting queue and
//adds a callback to the pendingQueries cache
//returns false if there is no signature left on the message
//TODO CFE verify whole signature chain (do not forget to check expiration)
func VerifySignature(body rainslib.MessageBodyWithSig, token rainslib.Token, sender ConnInfo, c chan<- bool) bool {
	if c != nil {
		defer func(c chan<- bool) { c <- true }(c)
	}
	keyIDs := make(map[string]string)
	for _, sig := range body.Sigs() {
		if sig.KeySpace != rainslib.RainsKeySpace {
			log.Warn("Unsupported keyspace", "KeySpaceID", sig.KeySpace)
		}
		keyIDs[strconv.Itoa(int(sig.KeySpace))+body.GetContext()+body.GetSubjectZone()] = strconv.Itoa(int(sig.KeySpace))
	}
	if publicKeys, missingKeys, ok := publicKeysPresent(keyIDs); ok {
		//all public keys are present
		return validSignature(body, publicKeys)
	} else {
		missingKeys["a"] = true
		if c == nil {
			//This is the first pass, send queries for public keys and add msgBody to pendingQueryqueue
		} else {
			//check hard deadline and strip off signature with what we have so far.
		}
	}
	return false
}

//publicKeysPresent returns true if all public keys are in the cache together with a map of keys and missingKeys
func publicKeysPresent(keyIDs map[string]string) (map[string]rainslib.PublicKey, map[string]bool, bool) {
	allKeysPresent := true
	keys := make(map[string]rainslib.PublicKey)
	missingKeys := make(map[string]bool)
	for keyID, keySpace := range keyIDs {
		if key, ok := zoneKeys.Get(keyID); ok {
			if int64(key.(rainslib.PublicKey).ValidUntil) < time.Now().Unix() {
				log.Info("Key is not valid anymore")
				zoneKeys.Remove(keyID)
				allKeysPresent = false
				missingKeys[keyID] = true
			} else {
				keys[keySpace] = key.(rainslib.PublicKey)
			}
		} else {
			allKeysPresent = false
			missingKeys[keyID] = true
		}
	}
	return keys, missingKeys, allKeysPresent
}

//validSignature validates the signatures on a MessageBodyWithSig and strips all signatures away that are not valid.
//Returns false If there are no signatures left
func validSignature(body rainslib.MessageBodyWithSig, keys map[string]rainslib.PublicKey) bool {
	switch body := body.(type) {
	case *rainslib.AssertionBody:
		return validAssertionSignatures(body, keys)
	case *rainslib.ShardBody:
		//TODO CFE implement this case
		log.Warn("Not yet supported CFE")
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
	assertionStub.DeleteAllSigs()
	bareAssertion := msgParser.RevParseSignedAssertion(assertionStub)
	for i, sig := range body.Signatures {
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Warn("signature expired", "expTime", sig.ValidUntil)
			body.DeleteSig(i)
		} else if newSig := GenerateHMAC([]byte(bareAssertion), sig.Algorithm, keys[strconv.Itoa(int(sig.KeySpace))].Key)[len(bareAssertion):]; !bytes.Equal(newSig, sig.Data) {
			log.Warn("signatures do not match", "signature", sig.Data, "calculatedSig", newSig)
			body.DeleteSig(i)
		}
	}
	return len(body.Sigs()) > 0
}

//Delegate adds the given public key to the zoneKeyCache
func Delegate(context string, zone string, cipherType rainslib.AlgorithmType, keySpace rainslib.KeySpaceID, key []byte, until uint) {
	pubKey := rainslib.PublicKey{Type: cipherType, Key: key, ValidUntil: until}
	ks := strconv.Itoa(int(keySpace))
	zoneKeys.Add(ks+context+zone, pubKey)
}
