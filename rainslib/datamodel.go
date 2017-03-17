package rainslib

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

//AssertionBody contains information about the assertion
type AssertionBody struct {
	//Mandatory
	SubjectName string
	Content     Object
	//Optional for contained assertions
	Signature   []Signature
	SubjectZone string
	Context     string
}

//ShardBody contains information about the shard
type ShardBody struct {
	//Mandatory
	Content []AssertionBody
	//Optional for contained shards
	Signatures  []Signature
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
}

//ZoneBody contains information about the zone
type ZoneBody struct {
	//Mandatory
	Signatures  []Signature
	SubjectZone string
	Context     string
	Content     []MessageBody //TODO can be assert and/or shardbody but not zonebody, how do we want to handle that?
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
	Options []int
}

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
	Algorithm  CipherType
	ValidSince int
	ValidUntil int
	Data       []byte
}

//CipherType is the type of a cipher
type CipherType int

const (
	Sha256 CipherType = iota
)

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
}
