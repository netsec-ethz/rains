package rainslib

import (
	log "github.com/inconshreveable/log15"
)

//RainsMessage contains the data of a message
type RainsMessage struct {
	//Mandatory
	Token   Token
	Content []MessageBody

	//Optional
	Signatures   []Signature
	Capabilities string
}

//Token is a byte slice with maximal length 32
type Token []byte

//MessageBody can be either an Assertion, Shard, Zone, Query or Notification body
type MessageBody interface {
}

//MessageBodyWithSig can be either an Assertion, Shard or Zone
type MessageBodyWithSig interface {
	Sigs() []Signature
	DeleteSig(int)
	DeleteAllSigs()
	GetContext() string
	GetSubjectZone() string
	CreateStub() MessageBodyWithSig
}

//AssertionBody contains information about the assertion
type AssertionBody struct {
	//Mandatory
	SubjectName string
	Content     Object
	//Optional for contained assertions
	Signatures  []Signature
	SubjectZone string
	Context     string
}

//Sigs return the assertion's signatures
func (a *AssertionBody) Sigs() []Signature {
	return a.Signatures
}

//DeleteSig deletes ith signature
func (a *AssertionBody) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (a *AssertionBody) DeleteAllSigs() {
	a.Signatures = []Signature{}
}

//GetContext returns the context of the assertion
func (a *AssertionBody) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the zone of the assertion
func (a *AssertionBody) GetSubjectZone() string {
	return a.SubjectZone
}

//CreateStub creates a copy of the assertion without the signatures.
func (a *AssertionBody) CreateStub() MessageBodyWithSig {
	stub := &AssertionBody{}
	*stub = *a
	stub.DeleteAllSigs()
	return stub
}

//ShardBody contains information about the shard
type ShardBody struct {
	//Mandatory
	Content []*AssertionBody
	//Optional for contained shards
	Signatures  []Signature
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
}

//Sigs return the shard's signatures
func (s *ShardBody) Sigs() []Signature {
	return s.Signatures
}

//DeleteSig deletes ith signature
func (s *ShardBody) DeleteSig(i int) {
	s.Signatures = append(s.Signatures[:i], s.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (s *ShardBody) DeleteAllSigs() {
	s.Signatures = []Signature{}
	for _, assertion := range s.Content {
		assertion.DeleteAllSigs()
	}
}

//GetContext returns the context of the shard
func (s *ShardBody) GetContext() string {
	return s.Context
}

//GetSubjectZone returns the zone of the shard
func (s *ShardBody) GetSubjectZone() string {
	return s.SubjectZone
}

//CreateStub creates a copy of the shard and its contained assertions without the signatures.
func (s *ShardBody) CreateStub() MessageBodyWithSig {
	stub := &ShardBody{}
	*stub = *s
	stub.Content = []*AssertionBody{}
	for _, assertion := range s.Content {
		stub.Content = append(stub.Content, assertion.CreateStub().(*AssertionBody))
	}
	stub.DeleteAllSigs()
	return stub
}

//ZoneBody contains information about the zone
type ZoneBody struct {
	//Mandatory
	Signatures  []Signature
	SubjectZone string
	Context     string
	Content     []MessageBodyWithSig
}

//Sigs return the zone's signatures
func (z *ZoneBody) Sigs() []Signature {
	return z.Signatures
}

//DeleteSig deletes ith signature
func (z *ZoneBody) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (z *ZoneBody) DeleteAllSigs() {
	z.Signatures = []Signature{}
	for _, body := range z.Content {
		switch body := body.(type) {
		case *AssertionBody:
			body.DeleteAllSigs()
		case *ShardBody:
			body.DeleteAllSigs()
		default:
			log.Warn("Datamodel: Unknown message body", "messageBody", body)
		}
	}
}

//GetContext returns the context of the zone
func (z *ZoneBody) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the zone of the zone
func (z *ZoneBody) GetSubjectZone() string {
	return z.SubjectZone
}

//CreateStub creates a copy of the zone and the contained shards and assertions without the signatures.
func (z *ZoneBody) CreateStub() MessageBodyWithSig {
	stub := &ZoneBody{}
	*stub = *z
	stub.Content = []MessageBodyWithSig{}
	for _, body := range z.Content {
		switch body := body.(type) {
		case *AssertionBody:
			stub.Content = append(stub.Content, body.CreateStub())
		case *ShardBody:
			stub.Content = append(stub.Content, body.CreateStub())
		default:
			log.Warn("Datamodel: Unknown message body", "messageBody", body)
		}
	}
	stub.DeleteAllSigs()
	return stub
}

//QueryBody contains information about the query
type QueryBody struct {
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
	MinE2ELatency QueryOptions = 1 + iota
	MinLastHopAnswerSize
	MinInfoLeakage
	CachedAnswersOnly
	ExpiredAssertionsOk
	TokenTracing
	NoVerificationDelegation
	NoProactiveCaching
)

type ObjectType int

const (
	Name ObjectType = 1 + iota
	IP6Addr
	IP4Addr
	Redirection
	Delegation
	Nameset
	CertInfo
	ServiceInfo
	Registrar
	Registrant
	Infrakey
)

//SubjectAddr TODO correct?
type SubjectAddr struct {
	AddressFamily string
	PrefixLength  uint
	Address       string
}

//AddressAssertionBody contains information about the address assertion
type AddressAssertionBody struct {
	//Mandatory
	SubjectAddr
	Content []Object
	//Optional for contained address assertions
	Signatures []Signature
	Context    string
}

//AddressZoneBody contains information about the address zone
type AddressZoneBody struct {
	//Mandatory
	SubjectAddr
	Signatures []Signature
	Context    string
	Content    []AddressAssertionBody
}

//AddressQueryBody contains information about the address query
type AddressQueryBody struct {
	//Mandatory
	SubjectAddr
	Token   []byte
	Context string
	Types   []int
	//Optional
	Expires int
	Options []int
}

//NotificationBody contains information about the notification
type NotificationBody struct {
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
	RcvMalformatMsg    NotificationType = 400
	RcvInconsistentMsg NotificationType = 403
	NoAssertionsExist  NotificationType = 404
	MsgTooLarge        NotificationType = 413
	UnspecServerErr    NotificationType = 500
	ServerNotCapable   NotificationType = 501
	NoAssertionAvail   NotificationType = 504
)

//Signature TODO What does it contain
type Signature struct {
	KeySpace   KeySpaceID
	Algorithm  AlgorithmType
	ValidSince int
	ValidUntil int
	Data       []byte
}

//KeySpaceID identifies a key space
type KeySpaceID int

const (
	RainsKeySpace KeySpaceID = iota
)

//AlgorithmType is the type of a cipher
type AlgorithmType int

const (
	Sha256 AlgorithmType = iota
	Sha384
)

//PublicKey contains information about a public key
type PublicKey struct {
	//TODO CFE remove type if not needed anywhere
	Type       AlgorithmType
	Key        []byte
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

	//RevParseSignedMsgBody parses an MessageBodyWithSig to a byte slice representation
	RevParseSignedMsgBody(body MessageBodyWithSig) (string, error)
}
