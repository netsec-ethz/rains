package rainslib

import (
	"crypto/rand"
	"strconv"

	"fmt"

	"io"

	"encoding/hex"

	"net"

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

//MessageSectionWithSig can be either an Assertion, Shard or Zone
type MessageSectionWithSig interface {
	Sigs() []Signature
	AddSig(sig Signature)
	DeleteSig(int)
	DeleteAllSigs()
	GetContext() string
	GetSubjectZone() string
	CreateStub() MessageSectionWithSig
	ValidFrom() int64
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

//ValidFrom returns the earliest validFrom date of all contained signatures
func (a *AssertionSection) ValidFrom() int64 {
	valid := a.Signatures[0].ValidSince
	for _, sig := range a.Signatures[1:] {
		if sig.ValidSince < valid {
			valid = sig.ValidSince
		}
	}
	return valid
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (a *AssertionSection) ValidUntil() int64 {
	//FIXME CFE this is not correct. There might be a time interval between several signatures during which this assertion is not valid.
	//Return the latest time which is reachable with all contained signatures without gaps in between
	valid := a.Signatures[0].ValidUntil
	for _, sig := range a.Signatures[1:] {
		if sig.ValidSince > valid {
			valid = sig.ValidSince
		}
	}
	return valid
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

//ValidFrom returns the earliest validFrom date of all contained signatures
func (s *ShardSection) ValidFrom() int64 {
	valid := s.Signatures[0].ValidSince
	for _, sig := range s.Signatures[1:] {
		if sig.ValidSince < valid {
			valid = sig.ValidSince
		}
	}
	return valid
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (s *ShardSection) ValidUntil() int64 {
	//FIXME CFE this is not correct. There might be a time interval between several signatures during which this assertion is not valid.
	//Return the latest time which is reachable with all contained signatures without gaps in between
	valid := s.Signatures[0].ValidUntil
	for _, sig := range s.Signatures[1:] {
		if sig.ValidSince > valid {
			valid = sig.ValidSince
		}
	}
	return valid
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

//ValidFrom returns the earliest validFrom date of all contained signatures
func (z *ZoneSection) ValidFrom() int64 {
	valid := z.Signatures[0].ValidSince
	for _, sig := range z.Signatures[1:] {
		if sig.ValidSince < valid {
			valid = sig.ValidSince
		}
	}
	return valid
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (z *ZoneSection) ValidUntil() int64 {
	//FIXME CFE this is not correct. There might be a time interval between several signatures during which this assertion is not valid.
	//Return the latest time which is reachable with all contained signatures without gaps in between
	valid := z.Signatures[0].ValidUntil
	for _, sig := range z.Signatures[1:] {
		if sig.ValidSince > valid {
			valid = sig.ValidSince
		}
	}
	return valid
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

//SubjectAddr TODO correct?
type SubjectAddr struct {
	AddressFamily ObjectType
	PrefixLength  uint
	Address       net.IPAddr
}

//AddressAssertionSection contains information about the address assertion
type AddressAssertionSection struct {
	SubjectAddr SubjectAddr
	Content     []Object
	Signatures  []Signature
	Context     string
}

//AddressZoneSection contains information about the address zone
type AddressZoneSection struct {
	SubjectAddr SubjectAddr
	Content     []*AddressAssertionSection
	Signatures  []Signature
	Context     string
}

//AddressQuerySection contains information about the address query
type AddressQuerySection struct {
	SubjectAddr SubjectAddr
	Token       Token
	Context     string
	Types       []int
	Expires     int
	//Optional
	Options []int
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
	//TODO CFE remove type if not needed anywhere
	Type       SignatureAlgorithmType
	Key        interface{}
	ValidFrom  int64
	ValidUntil int64
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

//RainsMsgParser translates between byte slices and RainsMessage.
//It must always hold that: rainsMsg = ParseByteSlice(ParseRainsMsg(rainsMsg)) && byteMsg = ParseRainsMsg(ParseByteSlice(byteMsg))
type RainsMsgParser interface {
	//ParseByteSlice parses the byte slice to a RainsMessage.
	ParseByteSlice(msg []byte) (RainsMessage, error)

	//ParseRainsMsg parses a RainsMessage to a byte slice representation.
	ParseRainsMsg(msg RainsMessage) ([]byte, error)

	//Token extracts the token from the byte slice of a RainsMessage
	Token(msg []byte) (Token, error)

	//RevParseSignedMsgSection parses an MessageSectionWithSig to a string representation
	RevParseSignedMsgSection(section MessageSectionWithSig) (string, error)

	//RevParseAddressAssertion parses a address assertion to its string representation
	RevParseAddressAssertion(a *AddressAssertionSection) string

	//RevParseAddressZone parses a address zone to its string representation
	RevParseAddressZone(z *AddressZoneSection) string

	//ParseSignedAssertion parses a byte slice representation of an assertion to the internal representation of an assertion.
	//TODO CFE extend this method to also allow parsing shards and zones if necessary
	ParseSignedAssertion(assertion []byte) (*AssertionSection, error)
}

//ZoneFileParser is the interface for all parsers of zone files for RAINS
type ZoneFileParser interface {
	//ParseZoneFile takes as input a zoneFile and returns all contained assertions. A zoneFile has the following format:
	//:Z: <context> <zone> [(:S:<Shard Content>|:A:<Assertion Content>)*]
	//Shard Content: [(:A:<Assertion Content>)*]
	//Assertion Content: <subject-name>[(:objectType:<object data>)*]
	ParseZoneFile(zoneFile []byte) ([]*AssertionSection, error)
}

//PRG pseudo random generator
type PRG struct{}

func (prg PRG) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

//MsgFramer is used to frame rains messages before transmission and deframe on the receiving end.
type MsgFramer interface {
	//Frame takes a message and adds a frame to it
	Frame(msg []byte) ([]byte, error)

	//InitStream defines the stream from which Deframe() and Data() are extracting the information from
	InitStream(stream io.Reader)

	//Deframe extracts the next frame from the stream defined in InitStream().
	//It blocks until it encounters the delimiter.
	//It returns false when the stream was not initialized or is already closed.
	//The data is available through Data
	Deframe() bool

	//Data contains the frame read from the stream by Deframe
	Data() []byte
}
