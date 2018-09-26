package rainsd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/encoder"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

var serverConnInfo connection.Info
var authoritative map[zoneContext]bool
var roots *x509.CertPool

//capabilityHash contains the sha256 hash of this server's capability list
var capabilityHash string

//capabilityList contains the string representation of this server's capability list.
var capabilityList string

//Config contains configurations for this server
var Config rainsdConfig

//cert holds the tls certificate of this server
var cert tls.Certificate

//sigEncoder is used to translate a message or section into a signable format
var sigEncoder encoder.SignatureFormatEncoder

// globalTracer is used to report traces to the tracing server.
var globalTracer *Tracer

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	//general
	RootZonePublicKeyPath string

	//switchboard
	ServerAddress      connection.Info
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
	Capabilities            []message.Capability

	//verify
	ZoneKeyCacheSize           int
	ZoneKeyCacheWarnSize       int
	MaxPublicKeysPerZone       int
	PendingKeyCacheSize        int
	InfrastructureKeyCacheSize uint
	ExternalKeyCacheSize       uint
	DelegationQueryValidity    time.Duration //in seconds
	ReapVerifyTimeout          time.Duration //in seconds

	//engine
	AssertionCacheSize         int
	NegativeAssertionCacheSize int
	PendingQueryCacheSize      int
	RedirectionCacheSize       int
	RedirectionCacheWarnSize   int
	QueryValidity              time.Duration //in seconds
	AddressQueryValidity       time.Duration //in seconds
	ContextAuthority           []string
	ZoneAuthority              []string
	MaxCacheValidity           util.MaxCacheValidity //in hours
	ReapEngineTimeout          time.Duration         //in seconds
}

//msgSectionSender contains the message section section and connection infos about the sender
type msgSectionSender struct {
	Sender  connection.Info
	Section section.Section
	Token   token.Token
}

//sectionWithSigSender contains a section with a signature and connection infos about the sender
type sectionWithSigSender struct {
	Sender  connection.Info
	Section section.SecWithSig
	Token   token.Token
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
	AddCapabilityList(dstAddr connection.Info, capabilities []message.Capability) bool
	//GetConnection returns true and all cached connections to dstAddr.
	//GetConnection returns false if there is no cached connection to dstAddr.
	GetConnection(dstAddr connection.Info) ([]net.Conn, bool)
	//Get returns true and the capability list of dstAddr.
	//Get returns false if there is no capability list of dstAddr.
	GetCapabilityList(dstAddr connection.Info) ([]message.Capability, bool)
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
	Add(capabilities []message.Capability)
	//Get returns true and a pointer to the capability list from which the hash was taken if
	//present, otherwise false and nil.
	Get(hash []byte) ([]message.Capability, bool)
	//Len returns the number of elements currently in the cache.
	Len() int
}

//zonePublicKeyCache is used to store public keys of zones and a pointer to delegation assertions
//containing them.
type zonePublicKeyCache interface {
	//Add adds publicKey together with the assertion containing it to the cache. Returns false if
	//the cache exceeds a configured (during initialization of the cache) amount of entries. If the
	//cache is full it removes a public key according to some metric. The cache logs a message when
	//a zone has more than a certain (configurable) amount of public keys. (An external service can
	//then decide if it wants to blacklist a given zone). If the internal flag is set, the publicKey
	//will only be removed after it expired.
	Add(assertion *section.Assertion, publicKey keys.PublicKey, internal bool) bool
	//Get returns true, the assertion holding the returned public key, and a non expired public key
	//which can be used to verify a signature with sigMetaData. It returns false if there is no
	//valid matching public key in the cache.
	Get(zone, context string, sigMetaData signature.MetaData) (
		keys.PublicKey, *section.Assertion, bool)
	//RemoveExpiredKeys deletes all expired public keys from the cache.
	RemoveExpiredKeys()
	//Len returns the number of public keys currently in the cache.
	Len() int
}

//revZonePublicKeyCache is used to store public keys of addressZones and a pointer to delegation
//assertions containing them.
type revZonePublicKeyCache interface {
	//Add adds publicKey together with the assertion containing it to the cache. Returns false if
	//the cache exceeds a configured (during initialization of the cache) amount of entries. If the
	//cache is full it removes a public key according to some metric. The cache logs a message when
	//a zone has more than a certain (configurable) amount of public keys. (An external service can
	//then decide if it wants to blacklist a given zone). If the internal flag is set, the publicKey
	//will only be removed after it expired.
	Add(assertion *section.Assertion, publicKey keys.PublicKey, internal bool) bool
	//Get returns true, the assertion holding the returned public key, and a non expired public key
	//which can be used to verify a signature with sigMetaData. It returns false if there is no
	//valid matching public key in the cache.
	Get(zone, context string, sigMetaData signature.MetaData) (
		keys.PublicKey, *section.Assertion, bool)
	//RemoveExpiredKeys deletes all expired public keys from the cache.
	RemoveExpiredKeys()
	//Len returns the number of public keys currently in the cache.
	Len() int
}

type pendingKeyCache interface {
	//Add adds sectionSender to the cache and returns true if a new delegation should be sent.
	Add(sectionSender sectionWithSigSender, algoType algorithmTypes.Signature, phase int) bool
	//AddToken adds token to the token map where the value of the map corresponds to the cache entry
	//matching the given zone and cotext. Token is added to the map and the cache entry's token,
	//expiration and sendTo fields are updated only if a matching cache entry exists. False is
	//returned if no matching cache entry exists.
	AddToken(token token.Token, expiration int64, sendTo connection.Info, zone, context string) bool
	//GetAndRemove returns all sections who contain a signature matching the given parameter and
	//deletes them from the cache. The token map is updated if necessary.
	GetAndRemove(zone, context string, algoType algorithmTypes.Signature, phase int) []sectionWithSigSender
	//GetAndRemoveByToken returns all sections who correspond to token and deletes them from the
	//cache. Token is removed from the token map.
	GetAndRemoveByToken(token token.Token) []sectionWithSigSender
	//ContainsToken returns true if token is in the token map.
	ContainsToken(token token.Token) bool
	//RemoveExpiredValues deletes all sections of an expired entry and updates the token map if
	//necessary. It logs which sections are removed and to which server the query has been sent.
	RemoveExpiredValues()
	//Len returns the number of sections in the cache
	Len() int
}

//TODO CFE also add methods which can return queries which are answered by the section's content.
type pendingQueryCache interface {
	//Add adds sectionSender to the cache and returns false if the query is already in the cache.
	Add(sectionSender msgSectionSender) bool
	//AddToken adds token to the token map where the value of the map corresponds to the cache entry
	//matching the given (fully qualified) name, context and connection (sorted). Token is added to the
	//map and the cache entry's token, expiration and sendTo fields are updated only if a matching
	//cache entry exists. False is returned if no matching cache entry exists.
	AddToken(token token.Token, expiration int64, sendTo connection.Info, name, context string,
		types []object.Type) bool
	//GetQuery returns true and the query or addressQuery stored with token in the cache if there is
	//such an entry.
	GetQuery(token token.Token) (section.Section, bool)
	//AddAnswerByToken adds section to the cache entry matching token with the given deadline. It
	//returns true if there is a matching token in the cache and section is not already stored for
	//these pending queries. The pending queries are are not removed from the cache.
	AddAnswerByToken(section section.SecWithSig, token token.Token, deadline int64) bool
	//GetAndRemoveByToken returns all queries waiting for a response to a query message containing
	//token and deletes them from the cache if no other section has been added to this cache entry
	//since section has been added by AddAnswerByToken(). Token is removed from the token map.
	GetAndRemoveByToken(token token.Token, deadline int64) (
		[]msgSectionSender, []section.Section)
	//UpdateToken adds newToken to the token map, lets it point to the cache value pointed by
	//oldToken and removes oldToken from the token map if newToken is not already in the token map.
	//It returns false if there is already an entry for newToken in the token map.
	UpdateToken(oldToken, newToken token.Token) bool
	//RemoveExpiredValues deletes all queries of an expired entry and updates the token map if
	//necessary. It logs which queries are removed and from which server the query has come and to
	//which it has been sent.
	RemoveExpiredValues()
	//Len returns the number of queries in the cache
	Len() int
}

//assertionCache is used to store and efficiently lookup assertions
type assertionCache interface {
	//Add adds an assertion together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy. It also adds assertion to the consistency cache.
	Add(assertion *section.Assertion, expiration int64, isInternal bool) bool
	//Get returns true and a set of assertions matching the given key if there exist some. Otherwise
	//nil and false is returned. If strict is set only an exact match for the provided FQDN is returned
	// otherwise a search up the domain name hiearchy is performed.
	Get(fqdn, context string, objType object.Type, strict bool) ([]*section.Assertion, bool)
	//RemoveExpiredValues goes through the cache and removes all expired assertions from the
	//assertionCache and the consistency cache.
	RemoveExpiredValues()
	//RemoveZone deletes all assertions in the assertionCache and consistencyCache of the given
	//zone.
	RemoveZone(zone string)
	//Len returns the number of elements in the cache.
	Len() int
}

type negativeAssertionCache interface {
	//Add adds shard together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy. It also adds shard to the consistency cache.
	AddShard(shard *section.Shard, expiration int64, isInternal bool) bool
	//Add adds zone together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy. It also adds zone to the consistency cache.
	AddZone(zone *section.Zone, expiration int64, isInternal bool) bool
	//Get returns true and a set of shards and zones matching subjectZone and context and overlap
	//with interval if there exist some. When context is the empty string, a random context is
	//chosen. Otherwise nil and false is returned.
	Get(subjectZone, context string, interval section.Interval) ([]section.SecWithSigForward, bool)
	//RemoveExpiredValues goes through the cache and removes all expired shards and zones from the
	//assertionCache and the consistency cache.
	RemoveExpiredValues()
	//RemoveZone deletes all shards and zones in the assertionCache and consistencyCache of the
	//given subjectZone.
	RemoveZone(subjectZone string)
	//Len returns the number of elements in the cache.
	Len() int
}

type consistencyCache interface {
	//Add adds section to the consistency cache.
	Add(section section.SecWithSigForward)
	//Get returns all sections from the cache with the given zone and context that are overlapping
	//with interval.
	Get(subjectZone, context string, interval section.Interval) []section.SecWithSigForward
	//Remove deletes section from the consistency cache
	Remove(section section.SecWithSigForward)
}

//addressSectionCache implements a data structure for fast reverse lookup.
//All operations must be concurrency safe
type addressSectionCache interface {
	//AddAssertion adds an address Assertion section to the cache
	//Returns an error when it was not able to a add the assertion to the cache
	AddAddressAssertion(assertion *section.AddrAssertion) error
	//Get returns the most specific address assertion or zone in relation to the given netAddress' prefix.
	//If no address assertion or zone is found it return false
	Get(netAddr *net.IPNet, types []object.Type) (*section.AddrAssertion, bool)
	//DeleteExpiredElements removes all expired elements from the data structure.
	DeleteExpiredElements()
}

//redirectionCache can be used to lookup connection information based on a redirect or delegation
//name.
type redirectionCache interface {
	//AddName adds subjectZone to the cache if it has not already been added. Otherwise it updates
	//the expiration time in case it is larger
	AddName(subjectZone string, expiration int64, internal bool)
	//AddConnInfo returns true and adds connInfo to subjectZone in the cache if subjectZone is
	//already in the cache. Otherwise false is returned and connInfo is not added to the cache.
	AddConnInfo(subjectZone string, connInfo connection.Info, expiration int64) bool
	//GetConnInfos returns all non expired cached connection information stored to subjectZone.
	GetConnsInfo(subjectZone string) []connection.Info
	//RemoveExpiredValues removes all expired elements from the data structure.
	RemoveExpiredValues()
	//Len returns the number of elements in the cache.
	Len() int
}

//zoneContext stores a context and a zone
type zoneContext struct {
	Zone    string
	Context string
}

//zoneAndName contains zone and name which together constitute a fully qualified name
type zoneAndName struct {
	zone string
	name string
}

func (e *zoneAndName) fullyQualifiedName() string {
	return fmt.Sprintf("%s.%s", e.name, e.zone)
}
