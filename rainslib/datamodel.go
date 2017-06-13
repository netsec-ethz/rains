package rainslib

import (
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
)

//RainsMessage contains the data of a message
type RainsMessage struct {
	//Mandatory
	Token   Token
	Content []MessageSection

	//Optional
	Signatures []Signature
	//FIXME CFE capabilities can also be represented as a hash, how should we model this?
	Capabilities []Capability
}

//Token is a byte slice with maximal length 32
type Token [16]byte

func (t Token) String() string {
	return hex.EncodeToString(t[:])
}

//MessageSection can be either an Assertion, Shard, Zone, Query or Notification section
type MessageSection interface {
}

//Capability is a urn of a capability
type Capability string

const (
	NoCapability Capability = ""
	TLSOverTCP   Capability = "urn:x-rains:tlssrv"
)

//MessageSectionWithSig can be either an Assertion, Shard, Zone, AddressAssertion, AddressZone
type MessageSectionWithSig interface {
	Sigs() []Signature
	AddSig(sig Signature)
	DeleteSig(int)
	DeleteAllSigs()
	GetContext() string
	GetSubjectZone() string
	CreateStub() MessageSectionWithSig
	UpdateValidity(validSince, validUntil int64, maxValidity time.Duration)
	ValidSince() int64
	ValidUntil() int64
	Hash() string
}

//MessageSectionWithSigForward can be either an Assertion, Shard or Zone
type MessageSectionWithSigForward interface {
	Sigs() []Signature
	AddSig(sig Signature)
	DeleteSig(int)
	DeleteAllSigs()
	GetContext() string
	GetSubjectZone() string
	CreateStub() MessageSectionWithSig
	UpdateValidity(validSince, validUntil int64, maxValidity time.Duration)
	ValidSince() int64
	ValidUntil() int64
	Hash() string
	Interval
}

//Interval defines an interval over strings
type Interval interface {
	//Begin of the interval
	Begin() string
	//End of the interval
	End() string
}

//TotalInterval is an interval over the whole namespace
type TotalInterval struct{}

func (t TotalInterval) Begin() string {
	return ""
}

func (t TotalInterval) End() string {
	return ""
}

//StringInterval implements Interval for a single string value
type StringInterval struct {
	Name string
}

func (s StringInterval) Begin() string {
	return s.Name
}

func (s StringInterval) End() string {
	return s.Name
}

//Hashable can be implemented by objects that are not natively hashable.
type Hashable interface {
	//Hash must return a string uniquely identifying the object
	Hash() string
}

//AssertionSection contains information about the assertion
type AssertionSection struct {
	SubjectName string
	Content     []Object
	Signatures  []Signature
	SubjectZone string
	Context     string
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//Sigs return the assertion's signatures
func (a *AssertionSection) Sigs() []Signature {
	return a.Signatures
}

//AddSig adds the given signature
func (a *AssertionSection) AddSig(sig Signature) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *AssertionSection) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (a *AssertionSection) DeleteAllSigs() {
	a.Signatures = []Signature{}
}

//GetContext returns the context of the assertion
func (a *AssertionSection) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the zone of the assertion
func (a *AssertionSection) GetSubjectZone() string {
	return a.SubjectZone
}

//CreateStub creates a copy of the assertion without the signatures.
func (a *AssertionSection) CreateStub() MessageSectionWithSig {
	stub := &AssertionSection{}
	*stub = *a
	stub.DeleteAllSigs()
	return stub
}

//Begin returns the begining of the interval of this assertion.
func (a *AssertionSection) Begin() string {
	return a.SubjectName
}

//End returns the end of the interval of this assertion.
func (a *AssertionSection) End() string {
	return a.SubjectName
}

//UpdateValidity updates the validity of this assertion if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (a *AssertionSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if a.validSince == 0 {
		a.validSince = math.MaxInt64
	}
	if validSince < a.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			log.Warn("Assertion validity starts too far in the future. Drop Assertion.", "assertion", *a, "newValidSince", validSince)
			return
		}
		a.validSince = validSince
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the assertion in the cache. Validity exceeded upper bound", "assertion", *a, "newValidUntil", validUntil)
		} else {
			a.validUntil = validUntil
		}
	}
}

//ValidSince returns the earliest validSince date of all contained signatures
func (a *AssertionSection) ValidSince() int64 {
	return a.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (a *AssertionSection) ValidUntil() int64 {
	return a.validUntil
}

//Hash returns a string containing all information uniquely identifying an assertion.
func (a *AssertionSection) Hash() string {
	return fmt.Sprintf("%s_%s_%s_%v_%v", a.Context, a.SubjectZone, a.SubjectName, a.Content, a.Signatures)
}

//EqualContextZoneName return true if the given assertion has the same context, zone, name.
func (a *AssertionSection) EqualContextZoneName(assertion *AssertionSection) bool {
	return a.Context == assertion.Context &&
		a.SubjectZone == assertion.SubjectZone &&
		a.SubjectName == assertion.SubjectName
}

//ShardSection contains information about the shard
type ShardSection struct {
	Content     []*AssertionSection
	Signatures  []Signature
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//Sigs return the shard's signatures
func (s *ShardSection) Sigs() []Signature {
	return s.Signatures
}

//AddSig adds the given signature
func (s *ShardSection) AddSig(sig Signature) {
	s.Signatures = append(s.Signatures, sig)
}

//DeleteSig deletes ith signature
func (s *ShardSection) DeleteSig(i int) {
	s.Signatures = append(s.Signatures[:i], s.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (s *ShardSection) DeleteAllSigs() {
	s.Signatures = []Signature{}
	for _, assertion := range s.Content {
		assertion.DeleteAllSigs()
	}
}

//GetContext returns the context of the shard
func (s *ShardSection) GetContext() string {
	return s.Context
}

//GetSubjectZone returns the zone of the shard
func (s *ShardSection) GetSubjectZone() string {
	return s.SubjectZone
}

//CreateStub creates a copy of the shard and its contained assertions without the signatures.
func (s *ShardSection) CreateStub() MessageSectionWithSig {
	stub := &ShardSection{}
	*stub = *s
	stub.Content = []*AssertionSection{}
	for _, assertion := range s.Content {
		stub.Content = append(stub.Content, assertion.CreateStub().(*AssertionSection))
	}
	stub.DeleteAllSigs()
	return stub
}

//Begin returns the begining of the interval of this shard.
func (s *ShardSection) Begin() string {
	return s.RangeFrom
}

//End returns the end of the interval of this shard.
func (s *ShardSection) End() string {
	return s.RangeTo
}

//UpdateValidity updates the validity of this shard if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (s *ShardSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if s.validSince == 0 {
		s.validSince = math.MaxInt64
	}
	if validSince < s.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			log.Warn("Shard validity starts too far in the future. Drop Shard.", "shard", *s, "newValidSince", validSince)
			return
		}
		s.validSince = validSince
	}
	if validUntil > s.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			s.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the shard in the cache. Validity exceeded upper bound", "shard", *s, "newValidUntil", validUntil)
		} else {
			s.validUntil = validUntil
		}
	}
}

//ValidSince returns the earliest validSince date of all contained signatures
func (s *ShardSection) ValidSince() int64 {
	return s.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (s *ShardSection) ValidUntil() int64 {
	return s.validUntil
}

//Hash returns a string containing all information uniquely identifying a shard.
func (s *ShardSection) Hash() string {
	aHashes := ""
	for _, a := range s.Content {
		aHashes += a.Hash()
	}
	return fmt.Sprintf("%s_%s_%s_%s_%s_%v", s.Context, s.SubjectZone, s.RangeFrom, s.RangeTo, aHashes, s.Signatures)
}

//ZoneSection contains information about the zone
type ZoneSection struct {
	Signatures  []Signature
	SubjectZone string
	Context     string
	Content     []MessageSectionWithSig
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//Sigs return the zone's signatures
func (z *ZoneSection) Sigs() []Signature {
	return z.Signatures
}

//AddSig adds the given signature
func (z *ZoneSection) AddSig(sig Signature) {
	z.Signatures = append(z.Signatures, sig)
}

//DeleteSig deletes ith signature
func (z *ZoneSection) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (z *ZoneSection) DeleteAllSigs() {
	z.Signatures = []Signature{}
	for _, section := range z.Content {
		switch section := section.(type) {
		case *AssertionSection, *ShardSection:
			section.DeleteAllSigs()
		default:
			log.Warn("Unknown message section", "messageSection", section)
		}
	}
}

//GetContext returns the context of the zone
func (z *ZoneSection) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the zone of the zone
func (z *ZoneSection) GetSubjectZone() string {
	return z.SubjectZone
}

//CreateStub creates a copy of the zone and the contained shards and assertions without the signatures.
func (z *ZoneSection) CreateStub() MessageSectionWithSig {
	stub := &ZoneSection{}
	*stub = *z
	stub.Content = []MessageSectionWithSig{}
	for _, section := range z.Content {
		switch section := section.(type) {
		case *AssertionSection, *ShardSection:
			stub.Content = append(stub.Content, section.CreateStub())
		default:
			log.Warn("Unknown message section", "messageSection", section)
		}
	}
	stub.DeleteAllSigs()
	return stub
}

//Begin returns the begining of the interval of this zone.
func (z *ZoneSection) Begin() string {
	return ""
}

//End returns the end of the interval of this zone.
func (z *ZoneSection) End() string {
	return ""
}

//UpdateValidity updates the validity of this zone if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (z *ZoneSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if z.validSince == 0 {
		z.validSince = math.MaxInt64
	}
	if validSince < z.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			log.Warn("Zone validity starts too far in the future. Drop Zone.", "zone", *z, "newValidSince", validSince)
			return
		}
		z.validSince = validSince
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the zone in the cache. Validity exceeded upper bound", "zone", *z, "newValidUntil", validUntil)
		} else {
			z.validUntil = validUntil
		}
	}
}

//ValidSince returns the earliest validSince date of all contained signatures
func (z *ZoneSection) ValidSince() int64 {
	return z.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (z *ZoneSection) ValidUntil() int64 {
	return z.validUntil
}

//Hash returns a string containing all information uniquely identifying a shard.
func (z *ZoneSection) Hash() string {
	contentHashes := ""
	for _, v := range z.Content {
		switch v := v.(type) {
		case *AssertionSection, *ShardSection:
			contentHashes += v.Hash()
		default:
			log.Warn(fmt.Sprintf("not supported zone section content, must be assertion or shard, got %T", v))
		}
	}
	return fmt.Sprintf("%s_%s_%s_%v", z.Context, z.SubjectZone, contentHashes, z.Signatures)
}

//QuerySection contains information about the query
type QuerySection struct {
	//Mandatory
	Token   Token
	Name    string
	Context string
	Type    ObjectType
	Expires int64 //time when this query expires represented as the number of seconds elapsed since January 1, 1970 UTC

	//Optional
	Options []QueryOption
}

//ContainsOption returns true if the query contains the given query option.
func (q QuerySection) ContainsOption(option QueryOption) bool {
	for _, opt := range q.Options {
		if opt == option {
			return true
		}
	}
	return false
}

type QueryOption int

const (
	MinE2ELatency            QueryOption = 1
	MinLastHopAnswerSize     QueryOption = 2
	MinInfoLeakage           QueryOption = 3
	CachedAnswersOnly        QueryOption = 4
	ExpiredAssertionsOk      QueryOption = 5
	TokenTracing             QueryOption = 6
	NoVerificationDelegation QueryOption = 7
	NoProactiveCaching       QueryOption = 8
)

type ObjectType int

func (o ObjectType) String() string {
	return strconv.Itoa(int(o))
}

const (
	OTName        ObjectType = 1
	OTIP6Addr     ObjectType = 2
	OTIP4Addr     ObjectType = 3
	OTRedirection ObjectType = 4
	OTDelegation  ObjectType = 5
	OTNameset     ObjectType = 6
	OTCertInfo    ObjectType = 7
	OTServiceInfo ObjectType = 8
	OTRegistrar   ObjectType = 9
	OTRegistrant  ObjectType = 10
	OTInfraKey    ObjectType = 11
	OTExtraKey    ObjectType = 12
)

//AddressAssertionSection contains information about the address assertion
type AddressAssertionSection struct {
	SubjectAddr *net.IPNet
	Content     []Object
	Signatures  []Signature
	Context     string
	validSince  int64
	validUntil  int64
}

//Sigs return the assertion's signatures
func (a *AddressAssertionSection) Sigs() []Signature {
	return a.Signatures
}

//AddSig adds the given signature
func (a *AddressAssertionSection) AddSig(sig Signature) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *AddressAssertionSection) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (a *AddressAssertionSection) DeleteAllSigs() {
	a.Signatures = []Signature{}
}

//GetContext returns the context of the assertion
func (a *AddressAssertionSection) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the zone of the shard
func (a *AddressAssertionSection) GetSubjectZone() string {
	if a.Context == "." {
		//FIXME CFE how to find out authority when delegated???
		return "."
	}
	return strings.Split(a.Context, "cx-")[1]
}

//CreateStub creates a copy of the assertion without the signatures.
func (a *AddressAssertionSection) CreateStub() MessageSectionWithSig {
	stub := &AddressAssertionSection{}
	*stub = *a
	stub.DeleteAllSigs()
	return stub
}

//UpdateValidity updates the validity of this assertion if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (a *AddressAssertionSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if a.validSince == 0 {
		a.validSince = math.MaxInt64
	}
	if validSince < a.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			log.Warn("AddressAssertion validity starts too far in the future. Drop AddressAssertion.", "addressAssertion", *a, "newValidSince", validSince)
			return
		}
		a.validSince = validSince
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the addressAssertion in the cache. Validity exceeded upper bound", "addressAssertion", *a, "newValidUntil", validUntil)
		} else {
			a.validUntil = validUntil
		}
	}
}

//ValidSince returns the earliest ValidSince date of all contained signatures
func (a *AddressAssertionSection) ValidSince() int64 {
	return a.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (a *AddressAssertionSection) ValidUntil() int64 {
	return a.validUntil
}

//Hash returns a string containing all information uniquely identifying an assertion.
func (a *AddressAssertionSection) Hash() string {
	return fmt.Sprintf("%s_%s_%v_%v",
		a.Context,
		a.SubjectAddr,
		a.Content,
		a.Signatures)
}

//AddressZoneSection contains information about the address zone
type AddressZoneSection struct {
	SubjectAddr *net.IPNet
	Content     []*AddressAssertionSection
	Signatures  []Signature
	Context     string
	validSince  int64
	validUntil  int64
}

//Sigs return the zone's signatures
func (z *AddressZoneSection) Sigs() []Signature {
	return z.Signatures
}

//AddSig adds the given signature
func (z *AddressZoneSection) AddSig(sig Signature) {
	z.Signatures = append(z.Signatures, sig)
}

//DeleteSig deletes ith signature
func (z *AddressZoneSection) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (z *AddressZoneSection) DeleteAllSigs() {
	z.Signatures = []Signature{}
	for _, assertion := range z.Content {
		assertion.DeleteAllSigs()
	}
}

//GetContext returns the context of the zone
func (z *AddressZoneSection) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the zone of the shard
func (z *AddressZoneSection) GetSubjectZone() string {
	if z.Context == "." {
		//FIXME CFE how to find out authority when delegated???
		return "."
	}
	return strings.Split(z.Context, "cx-")[1]
}

//CreateStub creates a copy of the zone and the contained shards and assertions without the signatures.
func (z *AddressZoneSection) CreateStub() MessageSectionWithSig {
	stub := &AddressZoneSection{}
	*stub = *z
	stub.Content = []*AddressAssertionSection{}
	for _, assertion := range z.Content {
		stub.Content = append(stub.Content, assertion.CreateStub().(*AddressAssertionSection))
	}
	stub.DeleteAllSigs()
	return stub
}

//UpdateValidity updates the validity of this addressZone if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (z *AddressZoneSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if z.validSince == 0 {
		z.validSince = math.MaxInt64
	}
	if validSince < z.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			log.Warn("AddressZone validity starts too far in the future. Drop addressZone.", "addressZone", *z, "newValidSince", validSince)
			return
		}
		z.validSince = validSince
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the addressZone in the cache. Validity exceeded upper bound", "addressZone", *z, "newValidUntil", validUntil)
		} else {
			z.validUntil = validUntil
		}
	}
}

//ValidSince returns the earliest validSince date of all contained signatures
func (z *AddressZoneSection) ValidSince() int64 {
	return z.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (z *AddressZoneSection) ValidUntil() int64 {
	return z.validUntil
}

//Hash returns a string containing all information uniquely identifying a shard.
func (z *AddressZoneSection) Hash() string {
	contentHashes := ""
	for _, a := range z.Content {
		contentHashes += a.Hash()
	}
	return fmt.Sprintf("%s_%s_%s_%v",
		z.Context,
		z.SubjectAddr,
		contentHashes,
		z.Signatures)
}

//AddressQuerySection contains information about the address query
type AddressQuerySection struct {
	SubjectAddr *net.IPNet
	Token       Token
	Context     string
	Types       ObjectType
	Expires     int64
	//Optional
	Options []QueryOption
}

//ContainsOption returns true if the address query contains the given query option.
func (q AddressQuerySection) ContainsOption(option QueryOption) bool {
	for _, opt := range q.Options {
		if opt == option {
			return true
		}
	}
	return false
}

//NotificationSection contains information about the notification
type NotificationSection struct {
	//Mandatory
	Token Token
	Type  NotificationType
	//Optional
	Data string
}

type NotificationType int

const (
	Heartbeat          NotificationType = 100
	CapHashNotKnown    NotificationType = 399
	BadMessage         NotificationType = 400
	RcvInconsistentMsg NotificationType = 403
	NoAssertionsExist  NotificationType = 404
	MsgTooLarge        NotificationType = 413
	UnspecServerErr    NotificationType = 500
	ServerNotCapable   NotificationType = 501
	NoAssertionAvail   NotificationType = 504
)

//Signature on a Rains message or section
type Signature struct {
	KeySpace   KeySpaceID
	Algorithm  SignatureAlgorithmType
	ValidSince int64
	ValidUntil int64
	Data       interface{}
}

//KeySpaceID identifies a key space
type KeySpaceID int

const (
	RainsKeySpace KeySpaceID = 0
)

//AlgorithmType specifies an identifier an algorithm
//TODO CFE how do we want to distinguish SignatureAlgorithmType and HashAlgorithmType
type KeyAlgorithmType int

func (k KeyAlgorithmType) String() string {
	return strconv.Itoa(int(k))
}

//SignatureAlgorithmType specifies a signature algorithm type
type SignatureAlgorithmType int

const (
	Ed25519  SignatureAlgorithmType = 1
	Ed448    SignatureAlgorithmType = 2
	Ecdsa256 SignatureAlgorithmType = 3
	Ecdsa384 SignatureAlgorithmType = 4
)

//FIXME CFE are these types necessary???
//Ed25519PublicKey is a 32-byte bit string
type Ed25519PublicKey [32]byte

//Ed448PublicKey is a 57-byte bit string
type Ed448PublicKey [57]byte

type Ecdsa256PublicKey struct {
	//TODO to implement
}

type Ecdsa384PublicKey struct {
	//TODO to implement
}

//HashAlgorithmType specifies a hash algorithm type
type HashAlgorithmType int

const (
	NoHashAlgo HashAlgorithmType = 0
	Sha256     HashAlgorithmType = 1
	Sha384     HashAlgorithmType = 2
	Sha512     HashAlgorithmType = 3
)

//PublicKey contains information about a public key
type PublicKey struct {
	Type       SignatureAlgorithmType
	KeySpace   KeySpaceID
	Key        interface{}
	ValidSince int64
	ValidUntil int64
}

//NameObject contains a name associated with a name as an alias. Types specifies for which object types the alias is valid
type NameObject struct {
	Name string
	//Types for which the Name is valid
	Types []ObjectType
}

//NamesetExpression  encodes a modified POSIX Extended Regular Expression format
type NamesetExpression string

//CertificateObject contains certificate information
type CertificateObject struct {
	Type     ProtocolType
	Usage    CertificateUsage
	HashAlgo HashAlgorithmType
	Data     []byte
}

type ProtocolType int

const (
	PTUnspecified ProtocolType = 0
	PTTLS         ProtocolType = 1
)

type CertificateUsage int

const (
	CUTrustAnchor CertificateUsage = 2
	CUEndEntity   CertificateUsage = 3
)

//ServiceInfo contains information how to access a named service
type ServiceInfo struct {
	Name     string
	Port     uint16
	Priority uint
}

//Object is a container for different values determined by the given type.
type Object struct {
	Type  ObjectType
	Value interface{}
}

//NetworkAddrType enumerates network address types
type NetworkAddrType int

const (
	TCP NetworkAddrType = iota
)

//ConnInfo contains address information about one actor of a connection of the declared type
type ConnInfo struct {
	Type NetworkAddrType

	TCPAddr *net.TCPAddr
}

//String returns the string representation of the connection information according to its type
func (c ConnInfo) String() string {
	switch c.Type {
	case TCP:
		return c.TCPAddr.String()
	default:
		log.Warn("Unsupported network address", "typeCode", c.Type)
		return ""
	}
}

//Hash returns a string containing all information uniquely identifying a ConnInfo.
func (c ConnInfo) Hash() string {
	return fmt.Sprintf("%v_%s", c.Type, c.String())
}

//Equal returns true if both Connection Information have the same type and the values corresponding to this type are identical.
func (c ConnInfo) Equal(conn ConnInfo) bool {
	if c.Type == conn.Type {
		switch c.Type {
		case TCP:
			return c.TCPAddr.IP.Equal(conn.TCPAddr.IP) && c.TCPAddr.Port == conn.TCPAddr.Port && c.TCPAddr.Zone == conn.TCPAddr.Zone
		default:
			log.Warn("Not supported network address type")
		}
	}
	return false
}

//RainsMsgParser can encode and decode RainsMessage.
//It is able to efficiently extract only the Token form an encoded RainsMessage
//It must always hold that: rainsMsg = Decode(Encode(rainsMsg)) && interface{} = Encode(Decode(interface{}))
type RainsMsgParser interface {
	//Decode extracts information from msg and returns a RainsMessage or an error
	Decode(msg []byte) (RainsMessage, error)

	//Encode encodes the given RainsMessage into a more compact representation.
	Encode(msg RainsMessage) ([]byte, error)

	//Token returns the extracted token from the given msg or an error
	Token(msg []byte) (Token, error)
}

//ZoneFileParser is the interface for all parsers of zone files for RAINS
type ZoneFileParser interface {
	//ParseZoneFile takes as input the content of a zoneFile and the name from which the data was loaded.
	//It returns all contained assertions or an error in case of failure
	ParseZoneFile(zoneFile []byte, filePath string) ([]*AssertionSection, error)
}

//SignatureFormatEncoder is used to deterministically transform a RainsMessage into a byte format that can be signed.
type SignatureFormatEncoder interface {
	//Encode transforms the given msg into a signable format.
	Encode(msg RainsMessage) []byte
}

//MsgFramer is used to frame and deframe rains messages and send or receive them on the initialized stream.
type MsgFramer interface {
	//Frame takes a message and adds a frame (if it not already has one) and send the framed message to the streamWriter defined in InitStream()
	Frame(msg []byte) error

	//InitStreams defines 2 streams. Deframe() and Data() are extracting the information from streamReader and Frame() is sending the data to streamWriter.
	//If a stream is readable and writable it is possible that streamReader = streamWriter
	InitStreams(streamReader io.Reader, streamWriter io.Writer)

	//DeFrame extracts the next frame from the streamReader defined in InitStream().
	//It blocks until it encounters the delimiter.
	//It returns false when the stream was not initialized or is already closed.
	//The data is available through Data
	DeFrame() bool

	//Data contains the frame read from the stream by DeFrame
	Data() []byte
}
