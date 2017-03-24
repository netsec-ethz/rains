package rainsd

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"io/ioutil"
	"math/big"
	"math/rand"
	"rains/rainslib"
	"strconv"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

const (
	configPath = "config/server.conf"
)

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	//switchboard
	ServerIPAddr    string
	ServerPort      uint16
	MaxConnections  uint
	KeepAlivePeriod time.Duration
	TCPTimeout      time.Duration
	CertificateFile string
	PrivateKeyFile  string

	//inbox
	MaxMsgLength           uint
	PrioBufferSize         uint
	NormalBufferSize       uint
	NotificationBufferSize uint
	PrioWorkerSize         uint
	NormalWorkerSize       uint
	NotificationWorkerSize uint
	CapabilitiesCacheSize  uint
	PeerToCapCacheSize     uint

	//verify
	ZoneKeyCacheSize          uint
	PendingSignatureCacheSize uint

	//engine
	AssertionCacheSize    uint
	PendingQueryCacheSize uint
}

//DefaultConfig is a rainsdConfig object containing default values
var defaultConfig = rainsdConfig{ServerIPAddr: "127.0.0.1", ServerPort: 5022, MaxConnections: 1000, KeepAlivePeriod: time.Minute, TCPTimeout: 5 * time.Minute,
	CertificateFile: "config/server.crt", PrivateKeyFile: "config/server.key", MaxMsgLength: 65536, PrioBufferSize: 1000, NormalBufferSize: 100000, PrioWorkerSize: 2,
	NormalWorkerSize: 10, ZoneKeyCacheSize: 1000, PendingSignatureCacheSize: 1000, AssertionCacheSize: 10000, PendingQueryCacheSize: 100, CapabilitiesCacheSize: 50,
	NotificationBufferSize: 20, NotificationWorkerSize: 2, PeerToCapCacheSize: 1000}

//ProtocolType enumerates protocol types
type ProtocolType int

const (
	TCP ProtocolType = iota
)

//ConnInfo contains address information about one actor of a connection of the declared type
//type 1 contains IPAddr and Port information
type ConnInfo struct {
	Type   ProtocolType
	IPAddr string
	Port   uint16
}

//MsgBodySender contains the message section body and connection infos about the sender
type MsgBodySender struct {
	Sender ConnInfo
	Msg    rainslib.MessageBody
	Token  rainslib.Token
}

//Capability is a type which defines what a server or client is capable of
type Capability string

const (
	NoCapability Capability = "none"
	TLSOverTCP   Capability = "urn:x-rains:tlssrv"
)

//IPAddrAndPort returns IP address and port in the format IPAddr:Port
func (c ConnInfo) IPAddrAndPort() string {
	return c.IPAddr + ":" + c.PortToString()
}

//PortToString return the port number as a string
func (c ConnInfo) PortToString() string {
	return strconv.Itoa(int(c.Port))
}

//Config contains configurations for this server
var Config rainsdConfig

//load config and stores it into global variable config
func loadConfig() {
	Config = defaultConfig
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Warn("Could not open config file...", "path", configPath, "error", err)
	}
	json.Unmarshal(file, &Config)
}

//CreateNotificationMsg creates a notification messages
func CreateNotificationMsg(token rainslib.Token, notificationType rainslib.NotificationType, data string) ([]byte, error) {
	content := []rainslib.MessageBody{&rainslib.NotificationBody{Type: rainslib.MsgTooLarge, Token: token, Data: data}}
	msg := rainslib.RainsMessage{Token: GenerateToken(), Content: content}
	//TODO CFE do we sign a notification msg?
	return msgParser.ParseRainsMsg(msg)
}

var counter = 0

//GenerateToken generates a new unique Token
func GenerateToken() rainslib.Token {
	//TODO CFE use uuid to create token
	counter++
	return rainslib.Token([]byte(strconv.Itoa(counter)))
}

//Cache implementations can have different replacement strategies
type Cache interface {
	//New creates a cache with the given parameters
	New(params ...interface{}) error
	//NewWithEvict creates a cache with the given parameters and a callback function when an element gets evicted
	NewWithEvict(onEvicted func(key interface{}, value interface{}), params ...interface{}) error
	//Add adds a value to the cache. If the cache is full the oldest element according to some metric will be replaced. Returns true if an eviction occurred.
	Add(key, value interface{}) bool
	//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
	Contains(key interface{}) bool
	//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
	Get(key interface{}) (interface{}, bool)
	//Keys returns a slice of the keys in the cache
	Keys() []interface{}
	//Len returns the number of elements in the cache.
	Len() int
	//Remove deletes the given key value pair from the cache
	Remove(key interface{})
	//RemoveOldest deletes the given key value pair from the cache according to some metric
	RemoveOldest()
}

//LRUCache is a concurrency safe cache with a least recently used eviction strategy
type LRUCache struct {
	Cache *lru.Cache
}

//New creates a lru cache with the given parameters
func (c *LRUCache) New(params ...interface{}) error {
	var err error
	c.Cache, err = lru.New(params[0].(int))
	return err
}

//NewWithEvict creates a lru cache with the given parameters and an eviction callback function
func (c *LRUCache) NewWithEvict(onEvicted func(key interface{}, value interface{}), params ...interface{}) error {
	var err error
	c.Cache, err = lru.NewWithEvict(params[0].(int), onEvicted)
	return err
}

//Add adds a value to the cache. If the cache is full the least recently used element will be replaced. Returns true if an eviction occurred.
func (c *LRUCache) Add(key, value interface{}) bool {
	return c.Cache.Add(key, value)
}

//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
func (c *LRUCache) Contains(key interface{}) bool {
	return c.Cache.Contains(key)
}

//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	return c.Cache.Get(key)
}

//Keys returns a slice of the keys in the cache sorted from oldest to newest
func (c *LRUCache) Keys() []interface{} {
	return c.Cache.Keys()
}

//Len returns the number of elements in the cache.
func (c *LRUCache) Len() int {
	return c.Cache.Len()
}

//Remove deletes the given key value pair from the cache
func (c *LRUCache) Remove(key interface{}) {
	c.Cache.Remove(key)
}

//RemoveOldest deletes the least recently used key value pair from the cache
func (c *LRUCache) RemoveOldest() {
	c.Cache.RemoveOldest()
}

//GenerateHMAC returns a hmac of the input message with the given hash function
func GenerateHMAC(msg []byte, hashType rainslib.SignatureAlgorithmType, key []byte) []byte {
	var h hash.Hash
	switch hashType {
	/*case rainslib.Sha256:
		h = hmac.New(sha512.New512_256, key)
	case rainslib.Sha384:
		h = hmac.New(sha512.New384, key)*/
	default:
		log.Warn("Not supported hash type.", "hashType", hashType)
	}
	return h.Sum(msg)
}

//SignData returns a signature of the input data signed with the specified signing algorithm and the given private key.
func SignData(algoType rainslib.SignatureAlgorithmType, privateKey interface{}, data []byte) interface{} {
	switch algoType {
	case rainslib.Ed25519:
		if pkey, ok := privateKey.(ed25519.PrivateKey); ok {
			return ed25519.Sign(pkey, data)
		}
		log.Warn("Could not cast key to ed25519.PrivateKey", "privateKey", privateKey)
	case rainslib.Ed448:
		log.Warn("Not yet Supported!")
	case rainslib.Ecdsa256:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			//TODO CFE or use sha256?
			hash := sha512.Sum512_256(data)
			return signEcdsa(pkey, data, hash[:])
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKey", privateKey)
	case rainslib.Ecdsa384:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha512.Sum384(data)
			return signEcdsa(pkey, data, hash[:])
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKey", privateKey)
	default:
		log.Warn("Signature algorithm type not supported", "type", algoType)
	}
	return nil
}

func signEcdsa(privateKey *ecdsa.PrivateKey, data, hash []byte) interface{} {
	//TODO CFE use other randomsource?
	r, s, err := ecdsa.Sign(rand.New(rand.NewSource(time.Now().UnixNano())), privateKey, hash)
	if err != nil {
		log.Warn("Could not sign data with Ecdsa256", "error", err)
	}
	return []*big.Int{r, s}
}

//VerifySignature returns true if the provided signature with the public key matches the data.
func VerifySignature(algoType rainslib.SignatureAlgorithmType, publicKey interface{}, data []byte, signature interface{}) bool {
	switch algoType {
	case rainslib.Ed25519:
		if pkey, ok := publicKey.(ed25519.PublicKey); ok {
			return ed25519.Verify(pkey, data, signature.([]byte))
		}
		log.Warn("Could not cast key to ed25519.PublicKey", "publicKey", publicKey)
	case rainslib.Ed448:
		log.Warn("Not yet Supported!")
	case rainslib.Ecdsa256:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			//TODO CFE or use sha256?
			if sig, ok := signature.([]*big.Int); ok && len(sig) == 2 {
				hash := sha512.Sum512_256(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not cast signature ", "signature", signature)
			return false
		}
		log.Warn("Could not cast key to ecdsa.PublicKey", "publicKey", publicKey)
	case rainslib.Ecdsa384:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := signature.([]*big.Int); ok && len(sig) == 2 {
				hash := sha512.Sum384(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not cast signature ", "signature", signature)
			return false
		}
		log.Warn("Could not cast key to ecdsa.PublicKey", "publicKey", publicKey)
	default:
		log.Warn("Signature algorithm type not supported", "type", algoType)
	}
	return false
}

//PendingSignatureCacheKey is the key for the pendingQuery cache
type PendingSignatureCacheKey struct {
	KeySpace    string
	Context     string
	SubjectZone string
}

//PendingSignatureCacheValue is the value received from the pendingQuery cache
type PendingSignatureCacheValue struct {
	ValidUntil  int64
	retries     int
	mux         sync.Mutex
	MsgBodyList MsgBodyWithSigList
}

//Retries returns the number of retries. If 0 no retries are attempted
func (v *PendingSignatureCacheValue) Retries() int {
	v.mux.Lock()
	defer func(v *PendingSignatureCacheValue) { v.mux.Unlock() }(v)
	return v.retries
}

//DecRetries decreses the retry value by 1
func (v *PendingSignatureCacheValue) DecRetries() {
	v.mux.Lock()
	if v.retries > 0 {
		v.retries--
	}
}

//MsgBodyWithSigList is a thread safe list of msgBodyWithSig
//To handle the case that we do not drop an incoming msgBody during the handling of the callback, we close the list after callback and return false
//Then the calling method can handle the new msgBody directly.
type MsgBodyWithSigList struct {
	mux                sync.Mutex
	closed             bool
	MsgBodyWithSigList []rainslib.MessageBodyWithSig
}

//Add adds an message body with signature to the list (It is thread safe)
//returns true if it was able to add the element to the list
func (l *MsgBodyWithSigList) Add(body rainslib.MessageBodyWithSig) bool {
	l.mux.Lock()
	defer func(l *MsgBodyWithSigList) { l.mux.Unlock() }(l)
	if !l.closed {
		l.MsgBodyWithSigList = append(l.MsgBodyWithSigList, body)
		return true
	}
	return false
}

//GetList returns the list and closes the data structure
func (l *MsgBodyWithSigList) GetListAndClose() []rainslib.MessageBodyWithSig {
	l.mux.Lock()
	defer func(l *MsgBodyWithSigList) { l.mux.Unlock() }(l)
	l.closed = true
	return l.MsgBodyWithSigList
}
