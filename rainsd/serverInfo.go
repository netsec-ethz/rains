package rainsd

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
)

var serverConnInfo rainslib.ConnInfo
var authoritative map[contextAndZone]bool
var roots *x509.CertPool
var msgParser rainslib.RainsMsgParser

//capabilityHash contains the sha256 hash of this server's capability list
var capabilityHash string

//capabilityList contains the string representation of this server's capability list.
var capabilityList string

//Config contains configurations for this server
var Config rainsdConfig

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	//general
	RootZonePublicKeyPath string

	//switchboard
	ServerAddress      rainslib.ConnInfo
	MaxConnections     int
	KeepAlivePeriod    time.Duration //in seconds
	TCPTimeout         time.Duration //in seconds
	TLSCertificateFile string
	TLSPrivateKeyFile  string

	//inbox
	MaxMsgByteLength        uint
	PrioBufferSize          uint
	NormalBufferSize        uint
	NotificationBufferSize  uint
	PrioWorkerCount         uint
	NormalWorkerCount       uint
	NotificationWorkerCount uint
	CapabilitiesCacheSize   int
	PeerToCapCacheSize      uint
	ActiveTokenCacheSize    uint
	Capabilities            []rainslib.Capability

	//verify
	ZoneKeyCacheSize           int
	ZoneKeyCacheWarnSize       int
	MaxPublicKeysPerZone       int
	PendingSignatureCacheSize  uint
	InfrastructureKeyCacheSize uint
	ExternalKeyCacheSize       uint
	DelegationQueryValidity    time.Duration //in seconds
	ReapVerifyTimeout          time.Duration //in seconds

	//engine
	AssertionCacheSize         int
	NegativeAssertionCacheSize int
	PendingQueryCacheSize      uint
	QueryValidity              time.Duration //in seconds
	AddressQueryValidity       time.Duration //in seconds
	ContextAuthority           []string
	ZoneAuthority              []string
	MaxCacheValidity           rainslib.MaxCacheValidity //in hours
	ReapEngineTimeout          time.Duration             //in seconds
}

//msgSectionSender contains the message section section and connection infos about the sender
type msgSectionSender struct {
	Sender  rainslib.ConnInfo
	Section rainslib.MessageSection
	Token   rainslib.Token
}

//sectionWithSigSender contains a section with a signature and connection infos about the sender
type sectionWithSigSender struct {
	Sender  rainslib.ConnInfo
	Section rainslib.MessageSectionWithSig
	Token   rainslib.Token
}

func (s *sectionWithSigSender) Hash() string {
	return fmt.Sprintf("%s_%s_%v", s.Sender.Hash(), s.Section.Hash(), s.Token)
}

//connectionCache stores persistent stream-oriented network connections.
type connectionCache interface {
	//AddConnection adds conn to the cache. If the cache capacity is reached, a connection from the cache will be
	//chosen by some metric, closed and removed.
	AddConnection(conn net.Conn)
	//AddCapability adds capabilities to the destAddr entry. It returns false if there is no entry
	//in the cache for dstAddr. If there is already a capability list associated with destAddr, it
	//will be overwritten.
	AddCapabilityList(dstAddr rainslib.ConnInfo, capabilities *[]rainslib.Capability) bool
	//GetConnection returns true and all cached connections to dstAddr.
	//GetConnection returns false if there is no cached connection to dstAddr.
	GetConnection(dstAddr rainslib.ConnInfo) ([]net.Conn, bool)
	//Get returns true and the capability list of dstAddr.
	//Get returns false if there is no capability list of dstAddr.
	GetCapabilityList(dstAddr rainslib.ConnInfo) ([]rainslib.Capability, bool)
	//CloseAndRemoveConnection closes conn and removes it from the cache.
	CloseAndRemoveConnection(conn net.Conn)
	//Len returns the number of connections currently in the cache.
	Len() int
}

//capabilityCache stores a mapping from a hash of a capability list to a pointer of the list.
type capabilityCache interface {
	//Add normalizes and serializes capabilities and then calculates a sha256 hash over it. It then
	//stores the mapping from the hash to a pointer of the list.
	//If the cache is full it removes a capability according to some metric
	Add(capabilities []rainslib.Capability)
	//Get returns true and a pointer to the capability list from which the hash was taken if
	//present, otherwise false and nil.
	Get(hash []byte) (*[]rainslib.Capability, bool)
	//Len returns the number of elements currently in the cache.
	Len() int
}

//zonePublicKeyCache is used to store public keys of zones and a pointer to assertions containing them.
type zonePublicKeyCache interface {
	//Add adds publicKey together with the assertion containing it to the cache. Returns false if
	//the cache exceeds a configured (during initialization of the cache) amount of entries. If the
	//cache is full it removes all public keys from a zone according to some metric. The cache logs
	//a message when a zone has more than a certain configurable (at initialization) amount of
	//public keys. An external service can then decide if it want to blacklist the given zone. If
	//the internal flag is set, publicKey will only be removed after it expired.
	Add(assertion *rainslib.AssertionSection, publicKey rainslib.PublicKey, internal bool) bool
	//Get returns true and a non expired public key which can be used to verify a signature with
	//sigMetaData. It returns false if there is no valid matching public key in the cache.
	Get(zone string, sigMetaData rainslib.SignatureMetaData) (rainslib.PublicKey, bool)
	//GetAllDelegations returns true and all valid cached delegation assertions for zone. It returns
	//false if there are no valid delegation assertions in the cache
	GetAllDelegations(zone string) ([]*rainslib.AssertionSection, bool)
	//RemoveExpiredKeys deletes all expired public keys from the cache.
	RemoveExpiredKeys()
	//Len returns the number of public keys currently in the cache.
	Len() int
}

//pendingSignatureCache stores all sections with a signature waiting for a public key to arrive so they can be verified
type pendingSignatureCache interface {
	//Add adds a section together with a validity to the cache. Returns true if there is not yet a pending query for this context and zone
	//If the cache is full it removes all section stored with the least recently used <context, zone> tuple.
	Add(context, zone string, value pendingSignatureCacheValue) bool
	//GetAllAndDelete returns true and all valid sections associated with the given context and zone if there are any. Otherwise false.
	//We simultaneously obtained all elements and close the set data structure. Then we remove the entry from the cache. If in the meantime an Add operation happened,
	//then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
	GetAllAndDelete(context, zone string) ([]sectionWithSigSender, bool)
	//RemoveExpiredSections goes through the cache and removes all expired sections. If for a given context and zone there is no section left it removes the entry from cache.
	RemoveExpiredSections()
	//Len returns the number of sections in the cache.
	Len() int
}

//pendingQueryCache stores connection information about queriers which are waiting for an assertion to arrive
type pendingQueryCache interface {
	//Add adds connection information together with a token and a validity to the cache.
	//Returns true and a newly generated token for the query to be sent out if cache does not contain a valid entry for context,zone,name,objType.Otherwise false is returned
	//If the cache is full it removes a pendingQueryCacheValue according to some metric.
	Add(context, zone, name string, objType []rainslib.ObjectType, value pendingQuerySetValue) (bool, rainslib.Token)
	//GetAllAndDelete returns true and all valid pendingQuerySetValues associated with the given token if there are any. Otherwise false
	//We simultaneously obtained all elements and close the set data structure. Then we remove the entry from the cache. If in the meantime an Add operation happened,
	//then Add will return false, as the set is already closed and the value is discarded. This case is expected to be rare.
	GetAllAndDelete(token rainslib.Token) ([]pendingQuerySetValue, bool)
	//RemoveExpiredValues goes through the cache and removes all expired values and tokens. If for a given context and zone there is no value left it removes the entry from cache.
	RemoveExpiredValues()
	//Len returns the number of elements in the cache.
	Len() int
}

//assertionCache is used to store and efficiently lookup assertions
type assertionCache interface {
	//Add adds an assertion together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy.
	Add(assertion *rainslib.AssertionSection, expiration int64, isInternal bool) bool
	//Get returns true and a set of assertions matching the given key if there exist some. Otherwise
	//nil and false is returned.
	Get(name, zone, context string, objType rainslib.ObjectType) ([]*rainslib.AssertionSection, bool)
	//RemoveExpiredValues goes through the cache and removes all expired assertions.
	RemoveExpiredValues()
	//RemoveZone deletes all assertions in the cache of the given zone.
	RemoveZone(zone string)
	//Len returns the number of elements in the cache.
	Len() int
}

type negativeAssertionCache interface {
	//Add adds shard together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy.
	AddShard(shard *rainslib.ShardSection, expiration int64, isInternal bool) bool
	//Add adds zone together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy.
	AddZone(zone *rainslib.ZoneSection, expiration int64, isInternal bool) bool
	//Get returns true and a set of shards and zones matching subjectZone and context and overlap
	//with interval if there exist some. When context is the empty string, a random context is
	//chosen. Otherwise nil and false is returned.
	Get(subjectZone, context string, interval rainslib.Interval) ([]rainslib.MessageSectionWithSigForward, bool)
	//RemoveExpiredValues goes through the cache and removes all expired shards and zones.
	RemoveExpiredValues()
	//RemoveZone deletes all shards and zones in the cache of the given subjectZone.
	RemoveZone(subjectZone string)
	//Len returns the number of elements in the cache.
	Len() int
}

//contextAndZone stores a context and a zone
type contextAndZone struct {
	Context string
	Zone    string
}

//setContainer is an interface for a set data structure where all operations are concurrency safe
type setContainer interface {
	//Add appends item to the current set if not already contained.
	//It returns false if it was not able to add the element because the underlying datastructure was deleted in the meantime
	Add(item rainslib.Hashable) bool

	//Delete removes item from the set.
	//Returns true if it was able to delete the element.
	Delete(item rainslib.Hashable) bool

	//GetAll returns all elements contained in the set.
	//If the underlying datastructure is deleted, the empty list is returned
	GetAll() []rainslib.Hashable

	//GetAllAndDelete returns all set elements and deletes the underlying datastructure.
	//If the underlying datastructure is already deleted, the empty list is returned.
	GetAllAndDelete() []rainslib.Hashable

	//Len returns the number of elements in the set.
	Len() int
}

type consistencyCache interface {
	//Add adds section to the consistency cache.
	Add(section rainslib.MessageSectionWithSigForward)
	//Get returns all sections from the cache with the given zone and context that are overlapping
	//with interval.
	Get(subjectZone, context string, interval rainslib.Interval) []rainslib.MessageSectionWithSigForward
	//Remove deletes section from the consistency cache
	Remove(section rainslib.MessageSectionWithSigForward)
}

//zoneAndName contains zone and name which together constitute a fully qualified name
type zoneAndName struct {
	zone string
	name string
}

//addressCache implements a data structure for fast reverse lookup.
//All operations must be concurrency safe
type addressSectionCache interface {
	//AddAssertion adds an address Assertion section to the cache
	//Returns an error when it was not able to a add the assertion to the cache
	AddAddressAssertion(assertion *rainslib.AddressAssertionSection) error
	//AddZone adds an address Zone section to the cache
	//Returns an error when it was not able to a add the assertion to the cache
	AddAddressZone(zone *rainslib.AddressZoneSection) error
	//Get returns the most specific address assertion or zone in relation to the given netAddress' prefix.
	//If no address assertion or zone is found it return false
	Get(netAddr *net.IPNet, types []rainslib.ObjectType) (*rainslib.AddressAssertionSection, *rainslib.AddressZoneSection, bool)
	//DeleteExpiredElements removes all expired elements from the data structure.
	DeleteExpiredElements()
}

//activeTokenCache implements a data structure to quickly determine if an incoming section will be processed with priority.
//All operations must be concurrency safe
//This cache keeps state of all active delegation queries. The return values can be used to log information about expired queries
//Based on the logs a higher level service can then decide to put a zone on a blacklist
//It also reduces the time sections have to stay in the pendingSignatureCache in times of high load
type activeTokenCache interface {
	//isPriority returns true and removes token from the cache if the section containing token has high priority
	IsPriority(token rainslib.Token) bool
	//AddToken adds token to the datastructure. The first incoming section with the same token will be processed with high priority
	//expiration is the query expiration time which determines how long the token is treated with high priority.
	//It returns false if the cache is full and the token is not added to the cache.
	AddToken(token rainslib.Token, expiration int64) bool
	//DeleteExpiredElements removes all expired tokens from the data structure and logs their information
	//It returns all expired tokens
	DeleteExpiredElements() []rainslib.Token
}
