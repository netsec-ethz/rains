package rainsd

import (
	"rains/rainslib"

	"time"

	log "github.com/inconshreveable/log15"
)

type publicKey struct {
	Type       rainslib.CipherType
	Key        []byte
	ValidUntil uint
}

//zoneKeys contains a set of zone public keys
var zoneKeys Cache

//pendingSignatures contains a mapping from all self issued pending queries to the set of messages waiting for it.
var pendingSignatures Cache

func init() {
	var err error
	loadConfig()
	//init cache
	zoneKeys = &LRUCache{}
	err = zoneKeys.New(int(Config.ZoneKeyCacheSize))
	if err != nil {
		log.Error("Cannot create zoneKeyCache", "error", err)
		panic(err)
	}
	pendingSignatures = &LRUCache{}
	err = pendingSignatures.New(int(Config.PendingSignatureCacheSize))
	if err != nil {
		log.Error("Cannot create pendingSignatureCache", "error", err)
		panic(err)
	}
}

//Verify verifies an assertion and strips away all signatures that do not verify. if no signatures remain, stop processing
//if channel c is present, it is used to notify the calling function that it has finished.
func Verify(msgSender MsgBodySender) {
	switch body := msgSender.Msg.(type) {
	case rainslib.AssertionBody:
		VerifySignature(msgSender.Msg, msgSender.Sender, nil)
	case rainslib.ShardBody:
		checkContainedAssertionsAndShards(msgSender)
		VerifySignature(msgSender.Msg, msgSender.Sender, nil)
	case rainslib.ZoneBody:
		checkContainedAssertionsAndShards(msgSender)
		VerifySignature(msgSender.Msg, msgSender.Sender, nil)
	case rainslib.QueryBody:
		if validQuery(body, msgSender.Sender) {
			Query(body)
		}
	default:
		log.Warn("Not supported Msg section body to verify", "MsgSectionBody", body)
	}
}

//validQuery validates the expiration time of the query
func validQuery(body rainslib.QueryBody, sender ConnInfo) bool {
	if int64(body.Expires) < time.Now().Unix() {
		log.Info("Query expired", "expirationTime", body.Expires)
		return false
	}
	log.Info("Query is valid", "QueryBody", body)
	return true
}

//checkContainedAssertionsAndShards compares the context and the subject zone of the outer message body with the contained message bodies.
//If they differ, a inconsistency notification msg is sent to the sender.
func checkContainedAssertionsAndShards(msgSender MsgBodySender) {
	switch msg := msgSender.Msg.(type) {
	case rainslib.ShardBody:
		for _, assertion := range msg.Content {
			if checkContainedAssertion(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
				break
			}

		}
	case rainslib.ZoneBody:
		for _, body := range msg.Content {
			//check contained assertion
			if assertion, ok := body.(rainslib.AssertionBody); ok {
				if checkContainedAssertion(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
					break
				}
				//check contained shard
			} else if shard, ok := body.(rainslib.ShardBody); ok {
				//check shard itself
				if shard.Context != msg.Context || shard.SubjectZone != msg.SubjectZone {
					log.Warn("Shard is inconsistent with Zone's context or subject zone", "ShardBody", body, "zoneBody", msg)
					sendNotificationMsg(msgSender.Token, msgSender.Sender, rainslib.RcvInconsistentMsg)
					break
				}
				//check assertions inside shard
				for _, assertion := range shard.Content {
					if checkContainedAssertion(assertion, msg.Context, msg.SubjectZone, msgSender.Token, msgSender.Sender) {
						break
					}
				}
			}
		}
	default:
		log.Warn("Message Body is not a Shard nor a Zone Body", "body", msg)
	}
}

//checkContainedAssertion checks if a contained shard's context and subject zone is equal to the parameters. If not a inconsistency notification message is sent to the sender.
func checkContainedAssertion(body rainslib.AssertionBody, context string, subjectZone string, token rainslib.Token, sender ConnInfo) bool {
	if body.Context != context || body.SubjectZone != subjectZone {
		log.Warn("Assertion is inconsistent with Shard's or zone's context or zone.", "Assertion", body, "context", context, "zone", subjectZone)
		sendNotificationMsg(token, sender, rainslib.RcvInconsistentMsg)
		return false
	}
	return true
}

//VerifySignature verifies all signatures and strips off invalid signatures. If the public key is missing it issues a query and put the msg body on waiting queue and
//adds a callback to the pendingQueries cache
//TODO CFE verify whole signature chain (do not forget to check expiration)
func VerifySignature(body rainslib.MessageBody, sender ConnInfo, c chan<- bool) {
	if c != nil {
		defer func(c chan<- bool) { c <- true }(c)
	}
}

//Delegate adds the given public key to the zoneKeyCache
func Delegate(context string, zone string, cipherType rainslib.CipherType, key []byte, until uint) {
	pubKey := publicKey{Type: cipherType, Key: key, ValidUntil: until}
	zoneKeys.Add(context+zone, pubKey)
}
