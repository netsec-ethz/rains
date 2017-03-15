package rainsd

import (
	"strings"

	"crypto/sha256"
	"strconv"

	"github.com/hashicorp/golang-lru"
	log "github.com/inconshreveable/log15"
)

//CipherType is the type of a cipher
type CipherType int

const (
	Sha256 CipherType = iota
)

type publicKey struct {
	Type       CipherType
	Key        []byte
	ValidUntil uint
}

//zoneKeyCache contains a set of zone public keys
//TODO CFE make an interface such that different cache implementation can be used in the future -> same as switchboard
var zoneKeys *lru.Cache

//queryCache contains a mapping from all self issued active queries to the set of go routines waiting for it.
//TODO CFE make an interface such that different cache implementation can be used in the future -> same as switchboard
var activeQueries *lru.Cache

func init() {
	var err error
	loadConfig()
	//init cache
	zoneKeys, err = lru.New(int(Config.ZoneKeyCacheSize))
	if err != nil {
		log.Error("Cannot create zoneKeyCache", "error", err)
		panic(err)
	}
	activeQueries, err = lru.New(int(Config.ActiveQueryCacheSize))
	if err != nil {
		log.Error("Cannot create activeQueryCache", "error", err)
		panic(err)
	}
}

//Verify verifies an assertion and strips away all signatures that do not verify. if no signatures remain, returns nil.
//TODO CFE implement properly, be able to process assertions, shard and zones!
func Verify(msgSender MsgSender) {
	verifySignature(msgSender)
	//TODO CFE parse query options
	//TODO CFE check expiration date
	//TODO CFE forward packet
	log.Warn("Good!")
	SendTo(msgSender.Msg, msgSender.Sender)
}

func verifySignature(msgSender MsgSender) {
	context := getValue(msgSender.Msg, ":cz:", ":zn:")
	zone := getValue(msgSender.Msg, ":zn:", ":sn:")
	if _, ok := zoneKeys.Get(context + zone); ok {
		//TODO CFE distinguish between assertions, shards and zones
		sig := getValue(msgSender.Msg, ":sig:", ":A:")
		values := strings.Split(sig, " ")
		//TODO CFE check expiration of signature
		//check signature value
		sigType, _ := strconv.Atoi(values[2])
		switch sigType {
		case int(Sha256):
			startIndex := strings.Index(string(msgSender.Msg), ":A:")
			calcSig := sha256.Sum256(msgSender.Msg[startIndex+3 : len(msgSender.Msg)])
			if string(calcSig[0:32]) == values[3] {
				//TODO CFE forward to engine
			} else {
				log.Warn("Signature do not match")
				return
			}
		default:
			log.Warn("Cipher Type does not exist.")
			return
		}

	} else {
		if activeQueries.Contains(context + zone) {
			//add msgSender to list in a concurrancy safe way!
		} else {
			//TODO CFE create Query
			query := ":Q:"
			//TODO CFE create destination ConnInfo
			//!!!!!!!!!!!!!!!!Port is not where this server is listening on !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			connInfo := ConnInfo{Type: TCP, IPAddr: "127.0.0.1", Port: 5021}
			SendTo([]byte(query), connInfo)
			//add msgSender to list in a concurrancy safe way!
			activeQueries.Add(context+zone, msgSender)
		}
	}
}

func getValue(message []byte, startToken string, endToken string) string {
	msg := string(message)
	startIndex := strings.Index(msg, startToken)
	endIndex := strings.Index(msg, endToken)
	if startIndex == -1 || endIndex == -1 {
		log.Warn("Msg does not contain token tag")
		return ""
	}
	return msg[startIndex+len(startToken) : endIndex]
}

//Delegate adds the given public key to the zoneKeyCache
func Delegate(context string, zone string, cipherType CipherType, key []byte, until uint) {
	pubKey := publicKey{Type: cipherType, Key: key, ValidUntil: until}
	zoneKeys.Add(context+zone, pubKey)
}
