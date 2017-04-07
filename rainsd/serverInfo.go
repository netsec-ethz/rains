package rainsd

import (
	"crypto/x509"
	"fmt"
	"net"
	"rains/rainslib"
	"strconv"
	"time"
)

var serverConnInfo ConnInfo
var roots *x509.CertPool
var msgParser rainslib.RainsMsgParser

//Config contains configurations for this server
var Config = defaultConfig

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	//switchboard
	ServerIPAddr    net.IP
	ServerPort      uint16
	MaxConnections  uint
	KeepAlivePeriod time.Duration
	TCPTimeout      time.Duration
	CertificateFile string
	PrivateKeyFile  string

	//inbox
	MaxMsgByteLength        uint
	PrioBufferSize          uint
	NormalBufferSize        uint
	NotificationBufferSize  uint
	PrioWorkerCount         uint
	NormalWorkerCount       uint
	NotificationWorkerCount uint
	CapabilitiesCacheSize   uint
	PeerToCapCacheSize      uint
	Capabilities            []rainslib.Capability

	//verify
	ZoneKeyCacheSize           uint
	PendingSignatureCacheSize  uint
	InfrastructureKeyCacheSize uint
	ExternalKeyCacheSize       uint
	DelegationQueryValidity    time.Duration

	//engine
	AssertionCacheSize         uint
	NegativeAssertionCacheSize uint
	PendingQueryCacheSize      uint
}

//DefaultConfig is a rainsdConfig object containing default values
var defaultConfig = rainsdConfig{ServerIPAddr: net.ParseIP("127.0.0.1"), ServerPort: 5022, MaxConnections: 1000, KeepAlivePeriod: time.Minute, TCPTimeout: 5 * time.Minute,
	CertificateFile: "config/server.crt", PrivateKeyFile: "config/server.key", MaxMsgByteLength: 65536, PrioBufferSize: 1000, NormalBufferSize: 100000, PrioWorkerCount: 2,
	NormalWorkerCount: 10, ZoneKeyCacheSize: 1000, PendingSignatureCacheSize: 1000, AssertionCacheSize: 10000, PendingQueryCacheSize: 100, CapabilitiesCacheSize: 50,
	NotificationBufferSize: 20, NotificationWorkerCount: 2, PeerToCapCacheSize: 1000, Capabilities: []rainslib.Capability{rainslib.TLSOverTCP}, InfrastructureKeyCacheSize: 10,
	ExternalKeyCacheSize: 5, DelegationQueryValidity: 5 * time.Second}

//ProtocolType enumerates protocol types
type ProtocolType int

const (
	TCP ProtocolType = iota
)

//ConnInfo contains address information about one actor of a connection of the declared type
type ConnInfo struct {
	Type   ProtocolType
	IPAddr net.IP
	Port   uint16
}

//String returns the string representation of the connection information according to its type
func (c ConnInfo) String() string {
	switch c.Type {
	case TCP:
		return c.IPAddr.String() + ":" + c.PortToString()
	default:
		return ""
	}
}

//PortToString return the port number as a string
func (c ConnInfo) PortToString() string {
	return strconv.Itoa(int(c.Port))
}

//AddressPair contains address information about both peers of a connection
type AddressPair struct {
	local  ConnInfo
	remote ConnInfo
}

//String returns the string representation of both connection information separated with a underscore
func (c AddressPair) String() string {
	return fmt.Sprintf("%#v_%#v", c.local, c.remote)
}

//msgSectionSender contains the message section section and connection infos about the sender
type msgSectionSender struct {
	Sender  ConnInfo
	Section rainslib.MessageSection
	Token   rainslib.Token
}

//sectionWithSigSender contains a section with a signature and connection infos about the sender
type sectionWithSigSender struct {
	Sender  ConnInfo
	Section rainslib.MessageSectionWithSig
	Token   rainslib.Token
}

//Capability is a type which defines what a server or client is capable of
type Capability string

const (
	NoCapability Capability = ""
	TLSOverTCP   Capability = "urn:x-rains:tlssrv"
)

type keyCacheKey struct {
	context string
	zone    string
	keyAlgo rainslib.KeyAlgorithmType
}

//connectionCache stores all active connections
type connectionCache interface {
	//Add adds a new connection to the cash. If for the given addrPair there is already a connection in the cache, the connection gets replaced with the new one.
	//Returns false if the cache already contained an entry for the addrPair.
	//If the cache is full it closes and removes a connection according to some metric
	Add(addrPair AddressPair, conn net.Conn) bool
	//Get returns a connection associated with the given four tuple.
	//If there is an element in the cache its recentness will be updated
	//Returns false if there is no connection for the given addrPair in the cache.
	Get(addrPair AddressPair) (net.Conn, bool)
	//Len returns the number of elements in the cache.
	Len() int
}

//capabilityCache contains known capabilities
type capabilityCache interface {
	//Add adds the capabilities to the cash and creates or updates a mapping between the capabilities and the hash thereof.
	//Returns true if the given connInfo was not yet in the cache and false if it updated the capabilities and the recentness of the entry for connInfo.
	//If the cache is full it removes a capability according to some metric
	Add(connInfo ConnInfo, capabilities []rainslib.Capability) bool
	//Get returns all capabilities associated with the given connInfo and updates the recentness of the entry.
	//It returns false if there exists no entry for connInfo
	Get(connInfo ConnInfo) ([]rainslib.Capability, bool)
	//GetFromHash returns true and the capabilities from which the hash was taken if present, otherwise false
	GetFromHash(hash []byte) ([]rainslib.Capability, bool)
}

//keyCache is the Interface which must be implemented by all caches for keys.
type keyCache interface {
	//Add adds the public key to the cash.
	//Returns true if the given public key was successfully added. If it was not possible to add the key it return false.
	//If the cache is full it removes all public keys from a keyCacheKey entry according to some metric
	//The cache makes sure that only a small limited amount of public keys (e.g. 3) can be stored associated with a keyCacheKey
	//If the internal flag is set, this key will only be removed after it expired.
	Add(key keyCacheKey, value rainslib.PublicKey, internal bool) bool
	//Get returns a valid public key matching the given keyCacheKey. It returns false if there exists no valid public key in the cache.
	//Get must always check the validity period of the public key before returning.
	Get(key keyCacheKey) (rainslib.PublicKey, bool)
	//RemoveExpiredKeys deletes a public key from the cache if it is expired
	RemoveExpiredKeys()
}

//publicKeyList provides some operation on a list of public keys.
type publicKeyList interface {
	//Add adds a public key to the list. If specified maximal list length is reached it removes the least recently used element.
	Add(key rainslib.PublicKey)
	//Get returns the first valid public key in the list. Returns false if there is no valid public key.
	Get() (rainslib.PublicKey, bool)
	//RemoveExpiredKeys deletes all expired keys from the list.
	RemoveExpiredKeys()
}

//pendingSignatureCacheValue is the value received from the pendingQuery cache
type pendingSignatureCacheValue struct {
	section    rainslib.MessageSectionWithSig
	ValidUntil int64
}

//pendingSignatureCache stores all sections with a signature waiting for a public key to arrive so they can be verified
type pendingSignatureCache interface {
	//Add adds a section together with a validity to the cache. Returns true if there is not yet a pending query for this context and zone
	//If the cache is full it removes all section stored with the least recently used <context, zone> tuple.
	Add(context, zone string, value pendingSignatureCacheValue) bool
	//GetAllAndDelete returns true and all valid sections associated with the given context and zone if there are any. Otherwise false.
	//We simultaneously obtained all elements and close the set data structure. Then we remove the entry from the cache. If in the meantime an Add operation happened,
	//then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
	GetAllAndDelete(context, zone string) ([]rainslib.MessageSectionWithSig, bool)
	//RemoveExpiredSections goes through the cache and removes all expired sections. If for a given context and zone there is no section left it removes the entry from cache.
	RemoveExpiredSections()
	//Len returns the number of sections in the cache.
	Len() int
}

//pendingSignatureCacheValue is the value received from the pendingQuery cache
type pendingQuerySetValue struct {
	ConnInfo   ConnInfo
	Token      rainslib.Token //Token from the received query
	ValidUntil int64
}

//pendingSignatureCacheValue is the value received from the pendingQuery cache
type pendingQueryCacheValue struct {
	set   setContainer
	token rainslib.Token //Token of this servers query
}

//pendingQueryCache stores connection information about queriers which are waiting for an assertion to arrive
type pendingQueryCache interface {
	//Add adds connection information together with a token and a validity to the cache.
	//Returns true and a newly generated token for the query to be sent out if cache does not contain a valid entry for context,zone,name,objType.Otherwise false is returned
	//If the cache is full it removes a pendingQueryCacheValue according to some metric.
	Add(context, zone, name string, objType rainslib.ObjectType, value pendingQuerySetValue) (bool, rainslib.Token)
	//GetAllAndDelete returns true and all valid pendingQuerySetValues associated with the given token if there are any. Otherwise false
	//We simultaneously obtained all elements and close the set data structure. Then we remove the entry from the cache. If in the meantime an Add operation happened,
	//then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
	GetAllAndDelete(token rainslib.Token) ([]pendingQuerySetValue, bool)
	//RemoveExpiredValues goes through the cache and removes all expired values and tokens. If for a given context and zone there is no value left it removes the entry from cache.
	RemoveExpiredValues()
	//Len returns the number of elements in the cache.
	Len() int
}

//assertionCacheValue is the value stored in the assertionCacheValue
type assertionCacheValue struct {
	section    *rainslib.AssertionSection
	validFrom  int64
	validUntil int64
}

//assertionCache is used to store and efficiently lookup assertions
type assertionCache interface {
	//Add adds an assertion together with a validity to the cache.
	//Returns true if cache did not already contain an entry for the given context,zone, name and objType
	//If the cache is full it removes an external assertionCacheValue according to some metric.
	Add(context, zone, name string, objType rainslib.ObjectType, internal bool, value assertionCacheValue) bool
	//Get returns a set of valid assertions matching the given key. Returns an empty list if there are none
	Get(context, zone, name string, objType rainslib.ObjectType) []*rainslib.AssertionSection
	//GetInRange returns a set of valid assertions in the range [beginRange, endRange] matching the given context and zone. Returns an empty list if there are none.
	GetInRange(context, zone, beginRange, endRange string) []*rainslib.AssertionSection
	//Len returns the number of elements in the cache.
	Len() int
	//RemoveExpiredValues goes through the cache and removes all expired values. If for a given context and zone there is no value left it removes the entry from cache.
	//If for a given context, zone, name and object type there is no value left it removes the entry from cache.
	RemoveExpiredValues()
}

//negativeAssertionCacheValue is the value stored in the negativeAssertionCache
type negativeAssertionCacheValue struct {
	section    rainslib.MessageSectionWithSig
	validFrom  int64
	validUntil int64
}

func (v negativeAssertionCacheValue) Begin() string {
	return v.section.Begin()
}

func (v negativeAssertionCacheValue) End() string {
	return v.section.End()
}

type negativeAssertionCache interface {
	//Add adds a shard or zone together with a validity to the cache.
	//Returns true if value was added to the cache.
	//If the cache is full it removes an external negativeAssertionCacheValue according to some metric.
	Add(context, zone string, internal bool, value negativeAssertionCacheValue) bool
	//Get returns true and the shortest valid shard/zone with the longest validity in range of the assertion if there exists one. Otherwise false is returned
	Get(context, zone string, assertion *rainslib.AssertionSection) (rainslib.MessageSectionWithSig, bool)
	//GetAll returns true and all valid sections of a given context and zone which intersect with the given Range if there is at least one. Otherwise false is returned
	GetAll(context, zone string, section rainslib.MessageSectionWithSig) ([]rainslib.MessageSectionWithSig, bool)
	//Len returns the number of elements in the cache.
	Len() int
	//RemoveExpiredValues goes through the cache and removes all expired values. If for a given context and zone there is no value left it removes the entry from cache.
	RemoveExpiredValues()
}

//contextAndZone stores a context and a zone
type contextAndZone struct {
	Context string
	Zone    string
}

//TODO CFE what should the name of this interface be?
type scanner interface {
	//Frame takes a message and adds a frame to it
	Frame(msg []byte) ([]byte, error)

	//Deframe extracts the next frame from a stream.
	//It blocks until it encounters the delimiter.
	//It returns false when the stream is closed.
	//The data is available through Data
	Deframe() bool

	//Data contains the frame read from the stream by Deframe
	Data() []byte
}

//setContainer is an interface for a set data structure where all operations are concurrency safe
type setContainer interface {
	//Add appends item to the current set if not already contained.
	//It returns false if it was not able to add the element because the underlying datastructure was deleted in the meantime
	Add(item interface{}) bool

	//Delete removes item from the set.
	//Returns true if it was able to delete the element.
	Delete(item interface{}) bool

	//GetAll returns all elements contained in the set.
	//If the underlying datastructure is deleted, the empty list is returned
	GetAll() []interface{}

	//GetAllAndDelete returns all set elements and deletes the underlying datastructure.
	//If the underlying datastructure is already deleted, the empty list is returned.
	GetAllAndDelete() []interface{}
}

//rangeQueryDataStruct is a datastructure which contains intervals and allows for interval intersection queries.
//All operations must be concurrency safe.
type rangeQueryDataStruct interface {
	//Add inserts item into the data structure
	Add(item rainslib.Interval) bool
	//Delete deletes item from the data structure
	Delete(item rainslib.Interval) bool
	//Get returns true all intervals which intersect with item if there are any. Otherwise false is returned
	Get(item rainslib.Interval) ([]rainslib.Interval, bool)
}
