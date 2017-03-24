package rainslib

import (
	log "github.com/inconshreveable/log15"
)

//RainsMessage contains the data of a message
type RainsMessage struct {
	//Mandatory
	Token   Token
	Content []MessageSection

	//Optional
	Signatures   []Signature
	Capabilities string
}

//Token is a byte slice with maximal length 32
type Token [16]byte

//MessageSection can be either an Assertion, Shard, Zone, Query or Notification section
type MessageSection interface {
}

//MessageSectionWithSig can be either an Assertion, Shard or Zone
type MessageSectionWithSig interface {
	Sigs() []Signature
	DeleteSig(int)
	DeleteAllSigs()
	GetContext() string
	GetSubjectZone() string
	CreateStub() MessageSectionWithSig
}

//AssertionSection contains information about the assertion
type AssertionSection struct {
	//Mandatory
	SubjectName string
	Content     []Object
	//Optional for contained assertions
	Signatures  []Signature
	SubjectZone string
	Context     string
}

//Sigs return the assertion's signatures
func (a *AssertionSection) Sigs() []Signature {
	return a.Signatures
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

//ShardSection contains information about the shard
type ShardSection struct {
	//Mandatory
	Content []*AssertionSection
	//Optional for contained shards
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

//ZoneSection contains information about the zone
type ZoneSection struct {
	//Mandatory
	Signatures  []Signature
	SubjectZone string
	Context     string
	Content     []MessageSectionWithSig
}

//Sigs return the zone's signatures
func (z *ZoneSection) Sigs() []Signature {
	return z.Signatures
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
		case *AssertionSection:
			section.DeleteAllSigs()
		case *ShardSection:
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
		case *AssertionSection:
			stub.Content = append(stub.Content, section.CreateStub())
		case *ShardSection:
			stub.Content = append(stub.Content, section.CreateStub())
		default:
			log.Warn("Unknown message section", "messageSection", section)
		}
	}
	stub.DeleteAllSigs()
	return stub
}

//QuerySection contains information about the query
type QuerySection struct {
	//Mandatory
	Token       Token
	SubjectName string
	Context     string
	Types       ObjectType

	//Optional
	Expires int
	Options []QueryOptions
}

type QueryOptions int

const (
	MinE2ELatency            QueryOptions = 1
	MinLastHopAnswerSize     QueryOptions = 2
	MinInfoLeakage           QueryOptions = 3
	CachedAnswersOnly        QueryOptions = 4
	ExpiredAssertionsOk      QueryOptions = 5
	TokenTracing             QueryOptions = 6
	NoVerificationDelegation QueryOptions = 7
	NoProactiveCaching       QueryOptions = 8
)

type ObjectType int

const (
	Name        ObjectType = 1
	IP6Addr     ObjectType = 2
	IP4Addr     ObjectType = 3
	Redirection ObjectType = 4
	Delegation  ObjectType = 5
	Nameset     ObjectType = 6
	CertInfo    ObjectType = 7
	ServiceInfo ObjectType = 8
	Registrar   ObjectType = 9
	Registrant  ObjectType = 10
	InfraKey    ObjectType = 11
	ExtraKey    ObjectType = 12
)

//SubjectAddr TODO correct?
type SubjectAddr struct {
	AddressFamily string
	PrefixLength  uint
	Address       string
}

//AddressAssertionSection contains information about the address assertion
type AddressAssertionSection struct {
	//Mandatory
	SubjectAddr
	Content []Object
	//Optional for contained address assertions
	Signatures []Signature
	Context    string
}

//AddressZoneSection contains information about the address zone
type AddressZoneSection struct {
	//Mandatory
	SubjectAddr
	Signatures []Signature
	Context    string
	Content    []AddressAssertionSection
}

//AddressQuerySection contains information about the address query
type AddressQuerySection struct {
	//Mandatory
	SubjectAddr
	Token   []byte
	Context string
	Types   []int
	//Optional
	Expires int
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
	ValidSince int
	ValidUntil int
	Data       []byte
}

//KeySpaceID identifies a key space
type KeySpaceID int

const (
	RainsKeySpace KeySpaceID = 0
)

//SignatureAlgorithmType specifies a signature algorithm type
type SignatureAlgorithmType int

const (
	Ed25519  SignatureAlgorithmType = 1
	Ed448    SignatureAlgorithmType = 2
	Ecdsa256 SignatureAlgorithmType = 3
	Ecdsa384 SignatureAlgorithmType = 4
)

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
	ValidUntil uint
}

//NamesetExpression  encodes a modified POSIX Extended Regular Expression format
type NamesetExpression string

//CertificateObject TODO define type
type CertificateObject string

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

	//Token extracts the token from the byte slice
	Token(msg []byte) (Token, error)

	//RevParseSignedMsgSection parses an MessageSectionWithSig to a byte slice representation
	RevParseSignedMsgSection(section MessageSectionWithSig) (string, error)
}
