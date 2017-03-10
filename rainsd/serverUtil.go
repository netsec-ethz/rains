package rainsd

type rainsdConfig struct {
	ServerIPAddr   string
	ServerPort     uint
	MaxConnections uint

	CertificateFile string
	PrivateKeyFile  string
}

//HostAddr contains a value which uniquely identifies a host (Rains Server or Client)
type HostAddr struct {
	IPAddr string
}

//ConnInfo contains all necessary information to uniquely identify a connection
type ConnInfo struct {
	Host HostAddr
	Port uint
}

//RainsMessage contains the data of a message
type RainsMessage struct {
	//Mandatory
	Token   []byte
	Content []MessageSection

	//Optional
	Signatures   []Signature
	Capabilities string
}

//MessageSection can be either an Assertion, Shard, Zone, or Query.
type MessageSection struct {
	Type int
	Body MessageBody //TODO create correct type
}

//MessageBody can be either an Assertion, Shard, Zone, or Query body
type MessageBody interface {
}

//AssertionBody contains information about the assertion
type AssertionBody struct {
	//Mandatory
	Subject string
	Content []Object
	//Optional for contained assertions
	Signatures  []Signature
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
	Range       []string
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
	Token   []byte
	Name    string
	Context []string
	Types   []int
	//Optional
	Expires int
	Options []int
}

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
	Token []byte
	Type  int
	//Optional
	Data string
}

//Signature TODO What does it contain
type Signature struct {
	AlgorithmID int
	ValidSince  int
	ValidUntil  int
	Data        []interface{}
}

//NamesetExpression  encodes a modified POSIX Extended Regular Expression format
type NamesetExpression string

//CertificateObject TODO define type
type CertificateObject string

//Object is a container for different values determined by the given type.
type Object struct {
	Type  int
	Value interface{}
}

//Config contains configurations for this server
var Config rainsdConfig
