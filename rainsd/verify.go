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

//Verify verifies an assertion and strips away all signatures that do not verify. if no signatures remain, returns nil.
func Verify(msgSender MsgBodySender) {
	switch body := msgSender.Msg.(type) {
	case rainslib.AssertionBody:
	case rainslib.ShardBody:
	case rainslib.ZoneBody:
	case rainslib.QueryBody:
		if validQuery(body, msgSender.Sender) {
			Query(body)
		}
	default:
		log.Warn("Not supported Msg section body to verify", "MsgSectionBody", body)
	}
	//TODO CFE verify that contained assertions or shard belong to the same context and zone
	//TODO CFE verify whole signature chain (do not forget to check expiration)
	//TODO CFE verify signature and strip off missing signatures (check hash of message) If public key is missing issue a query and put msg on waiting queue
	//TODO CFE parse query options
	//TODO CFE forward packet
	log.Info("Good!")
	SendTo([]byte("Test"), msgSender.Sender)
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

func validateSignature(body rainslib.MessageBody, sender ConnInfo) rainslib.MessageBody {
	return nil
}

//Delegate adds the given public key to the zoneKeyCache
func Delegate(context string, zone string, cipherType rainslib.CipherType, key []byte, until uint) {
	pubKey := publicKey{Type: cipherType, Key: key, ValidUntil: until}
	zoneKeys.Add(context+zone, pubKey)
}
