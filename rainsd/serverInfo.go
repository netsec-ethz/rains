package rainsd

import (
	"crypto/x509"
	"net"
	"rains/rainslib"
	"strconv"
	"sync"
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
	ServerIPAddr          net.IP
	ServerPort            uint16
	MaxConnections        uint
	KeepAlivePeriodMicros time.Duration
	TCPTimeoutMicros      time.Duration
	CertificateFile       string
	PrivateKeyFile        string

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

	//verify
	ZoneKeyCacheSize          uint
	PendingSignatureCacheSize uint

	//engine
	AssertionCacheSize    uint
	PendingQueryCacheSize uint
}

//DefaultConfig is a rainsdConfig object containing default values
var defaultConfig = rainsdConfig{ServerIPAddr: net.ParseIP("127.0.0.1"), ServerPort: 5022, MaxConnections: 1000, KeepAlivePeriodMicros: time.Minute, TCPTimeoutMicros: 5 * time.Minute,
	CertificateFile: "config/server.crt", PrivateKeyFile: "config/server.key", MaxMsgByteLength: 65536, PrioBufferSize: 1000, NormalBufferSize: 100000, PrioWorkerCount: 2,
	NormalWorkerCount: 10, ZoneKeyCacheSize: 1000, PendingSignatureCacheSize: 1000, AssertionCacheSize: 10000, PendingQueryCacheSize: 100, CapabilitiesCacheSize: 50,
	NotificationBufferSize: 20, NotificationWorkerCount: 2, PeerToCapCacheSize: 1000}

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

//IPAddrAndPort returns IP address and port in the format IPAddr:Port
func (c ConnInfo) IPAddrAndPort() string {
	return c.IPAddr.String() + ":" + c.PortToString()
}

//PortToString return the port number as a string
func (c ConnInfo) PortToString() string {
	return strconv.Itoa(int(c.Port))
}

//msgSectionSender contains the message section section and connection infos about the sender
type msgSectionSender struct {
	Sender ConnInfo
	Msg    rainslib.MessageSection
	Token  rainslib.Token
}

//Capability is a type which defines what a server or client is capable of
type Capability string

const (
	NoCapability Capability = ""
	TLSOverTCP   Capability = "urn:x-rains:tlssrv"
)

//cache implementations can have different replacement strategies
type cache interface {
	//New creates a cache with the given parameters
	New(params ...interface{}) error
	//NewWithEvict creates a cache with the given parameters and a callback function when an element gets evicted
	NewWithEvict(onEvicted func(key interface{}, value interface{}), params ...interface{}) error
	//Add adds a value to the cache. If the cache is full the oldest element according to some metric will be replaced. Returns true if it was able to add the element???
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
	//RemoveWithStrategy deletes the given key value pair from the cache according to some strategy
	RemoveWithStrategy()
}

//assertCache used for caching assertions, it allows range queries
type assertCache interface {
	cache
	//GetInRange returns sets of assertions grouped by context and zone which are in the given range.
	GetInRange(context, zone, begin, end string) []container
}

//pendingSignatureCacheKey is the key for the pendingQuery cache
type pendingSignatureCacheKey struct {
	KeySpace    string
	Context     string
	SubjectZone string
}

//pendingSignatureCacheValue is the value received from the pendingQuery cache
type pendingSignatureCacheValue struct {
	ValidUntil     int64
	retries        int
	mux            sync.Mutex
	MsgSectionList msgSectionWithSigList
}

//Retries returns the number of retries. If 0 no retries are attempted
func (v *pendingSignatureCacheValue) Retries() int {
	v.mux.Lock()
	defer func(v *pendingSignatureCacheValue) { v.mux.Unlock() }(v)
	return v.retries
}

//DecRetries decreses the retry value by 1
func (v *pendingSignatureCacheValue) DecRetries() {
	v.mux.Lock()
	if v.retries > 0 {
		v.retries--
	}
}

//assertionCacheKey is the key for the pendingQueryCache and the assertionCache.
type assertionCacheKey struct {
	Context     string
	SubjectZone string
	ObjectType  rainslib.ObjectType
	SubjectName string
}

//assertionCacheValue is the value type of the assertionCache.
type assertionCacheValue struct {
	ValidUntil int
	Retry      bool
	mux        sync.Mutex
	List       queryAnswerList
}

type queryAnswerList struct {
	ConnInfo ConnInfo
	Token    rainslib.Token
}

//negAssertionCacheKey is the key for the negAssertionCache
type negAssertionCacheKey struct {
	Context string
	Subject string
}

//msgSectionWithSigList is a thread safe list of msgSectionWithSig
//To handle the case that we do not drop an incoming msgSection during the handling of the callback, we close the list after callback and return false
//Then the calling method can handle the new msgSection directly.
type msgSectionWithSigList struct {
	mux                   sync.Mutex
	closed                bool
	MsgSectionWithSigList []rainslib.MessageSectionWithSig
}

//Add adds an message section with signature to the list (It is thread safe)
//returns true if it was able to add the element to the list
func (l *msgSectionWithSigList) Add(section rainslib.MessageSectionWithSig) bool {
	l.mux.Lock()
	defer func(l *msgSectionWithSigList) { l.mux.Unlock() }(l)
	if !l.closed {
		l.MsgSectionWithSigList = append(l.MsgSectionWithSigList, section)
		return true
	}
	return false
}

//GetList returns the list and closes the data structure
func (l *msgSectionWithSigList) GetListAndClose() []rainslib.MessageSectionWithSig {
	l.mux.Lock()
	defer func(l *msgSectionWithSigList) { l.mux.Unlock() }(l)
	l.closed = true
	return l.MsgSectionWithSigList
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

//container is an interface for a map data structure which might be concurrency safe
type container interface {
	//Add appends item to the current list.
	//It returns false if it was not able to add the element because the underlying datastructure was deleted in the meantime
	Add(item interface{}) bool

	//Delete removes item from the list.
	Delete(item interface{})

	//GetAll returns all elements contained in the datastructure
	GetAll() []interface{}

	//GetAllAndDelete returns all contained elements and deletes the datastructure.
	GetAllAndDelete() []interface{}
}
