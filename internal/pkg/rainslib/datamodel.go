package rainslib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/britram/borat"
	"golang.org/x/crypto/ed25519"
)

//RainsMessage represents a Message
type RainsMessage struct {
	//Capabilities is a slice of capabilities or the hash thereof which the server originating the
	//message has.
	Capabilities []Capability
	//Token is used to identify a message
	Token Token
	//Content is a slice of
	Content []MessageSection
	//Signatures authenticate the content of this message. An encoding of RainsMessage is signed by the infrastructure key of the originating server.
	Signatures []Signature
}

// MarshalCBOR writes the RAINS message to the provided writer.
// Implements the CBORMarshaler interface.
func (rm *RainsMessage) MarshalCBOR(w *borat.CBORWriter) error {
	if err := w.WriteTag(borat.CBORTag(0xE99BA8)); err != nil {
		return err
	}
	m := make(map[int]interface{})
	// A Message map MAY contain a signatures (0) key, whose value is an array
	// of Signatures over the entire message as defined in Section 5.13, to be
	// verified against the infrastructure key for the RAINS Server originating
	// the message.
	if len(rm.Signatures) > 0 {
		m[0] = rm.Signatures
	}
	// A Message map MAY contain a capabilities (1) key.
	if len(rm.Capabilities) > 0 {
		m[1] = rm.Capabilities
	}
	// A Message map MUST contain a token (2) key, whose value is a 16-byte array.
	m[2] = rm.Token
	// Message sections.
	// Each message section is a two element array [type, msgsection].
	msgsect := make([][2]interface{}, 0)
	for _, sect := range rm.Content {
		switch sect.(type) {
		case *AssertionSection:
			msgsect = append(msgsect, [2]interface{}{1, sect})
		case *ShardSection:
			msgsect = append(msgsect, [2]interface{}{2, sect})
		case *ZoneSection:
			msgsect = append(msgsect, [2]interface{}{3, sect})
		case *QuerySection:
			msgsect = append(msgsect, [2]interface{}{4, sect})
		case *NotificationSection:
			msgsect = append(msgsect, [2]interface{}{23, sect})
		default:
			return fmt.Errorf("unknown section type: %T", sect)
		}
	}
	m[23] = msgsect
	return w.WriteIntMap(m)
}

func (rm *RainsMessage) UnmarshalCBOR(r *borat.CBORReader) error {
	// First read a tag to ensure we are parsing a RainsMessage
	tag, err := r.ReadTag()
	if err != nil {
		return fmt.Errorf("failed to read tag: %v", err)
	}
	if tag != borat.CBORTag(0xE99BA8) {
		return fmt.Errorf("expected tag for RAINS message but got: %v", tag)
	}
	m, err := r.ReadIntMapUntagged()
	if err != nil {
		return fmt.Errorf("failed to read map: %v", err)
	}
	// Read the signatures
	if sigs, ok := m[0]; ok {
		rm.Signatures = make([]Signature, 0)
		// RAINS signatures have five common elements: the algorithm
		// identifier, a keyspace identifier, a keyphase identifier, a
		// valid-since timestamp, and a valid-until timestamp. Signatures are
		// represented as an array of these five values followed by additional
		// elements containing the signature data itself, according to the
		// algorithm identifier.
		for _, sig := range sigs.([][]interface{}) {
			alg := sig[0].(SignatureAlgorithmType)
			ks := sig[1].(KeySpaceID)
			kp := sig[2].(int)
			vs := sig[3].(int64)
			vu := sig[4].(int64)
			data := sig[5]
			s := Signature{
				PublicKeyID: PublicKeyID{
					Algorithm: alg,
					KeySpace:  ks,
					KeyPhase:  kp,
				},
				ValidSince: vs,
				ValidUntil: vu,
				Data:       data,
			}
			rm.Signatures = append(rm.Signatures, s)
		}
	}
	// Read the capabilities
	if caps, ok := m[1]; ok {
		rm.Capabilities = make([]Capability, 0)
		for _, cap := range caps.([]interface{}) {
			rm.Capabilities = append(rm.Capabilities, Capability(cap.(string)))
		}
	}
	// read the token
	if _, ok := m[2]; !ok {
		return fmt.Errorf("token missing from RAINS message: %v", m)
	}
	for i, val := range m[2].([]interface{}) {
		rm.Token[i] = byte(val.(uint64))
	}
	// read the message sections
	for _, elem := range m[23].([]interface{}) {
		elem := elem.([]interface{})
		t := elem[0].(uint64)
		switch t {
		case 1:
			// AssertionSection
			as := &AssertionSection{}
			if err := as.UnmarshalMap(elem[1].(map[int]interface{})); err != nil {
				return err
			}
			rm.Content = append(rm.Content, as)
		case 2:
			// ShardSection
			ss := &ShardSection{}
			if err := ss.UnmarshalMap(elem[1].(map[int]interface{})); err != nil {
				return err
			}
			rm.Content = append(rm.Content, ss)
		case 3:
			// ZoneSection
			zs := &ZoneSection{}
			if err := zs.UnmarshalMap(elem[1].(map[int]interface{})); err != nil {
				return err
			}
			rm.Content = append(rm.Content, zs)
		case 4:
			// QuerySection
			qs := &QuerySection{}
			if err := qs.UnmarshalMap(elem[1].(map[int]interface{})); err != nil {
				return err
			}
			rm.Content = append(rm.Content, qs)
		case 23:
			// NotificationSection
			ns := &NotificationSection{}
			if err := ns.UnmarshalMap(elem[1].(map[int]interface{})); err != nil {
				return err
			}
			rm.Content = append(rm.Content, ns)
		}
	}
	return nil
}

//Sort sorts the sections in m.Content first by Message Section Type Codes (see RAINS Protocol Specification) and
//second the sections of equal type according to their sort function.
func (m *RainsMessage) Sort() {
	var assertions []*AssertionSection
	var shards []*ShardSection
	var zones []*ZoneSection
	var queries []*QuerySection
	var addressAssertions []*AddressAssertionSection
	var addressZones []*AddressZoneSection
	var addressQueries []*AddressQuerySection
	var notifications []*NotificationSection
	for _, sec := range m.Content {
		sec.Sort()
		switch sec := sec.(type) {
		case *AssertionSection:
			assertions = append(assertions, sec)
		case *ShardSection:
			shards = append(shards, sec)
		case *ZoneSection:
			zones = append(zones, sec)
		case *QuerySection:
			queries = append(queries, sec)
		case *NotificationSection:
			notifications = append(notifications, sec)
		case *AddressAssertionSection:
			addressAssertions = append(addressAssertions, sec)
		case *AddressZoneSection:
			addressZones = append(addressZones, sec)
		case *AddressQuerySection:
			addressQueries = append(addressQueries, sec)
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", sec))
		}
	}
	sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	sort.Slice(shards, func(i, j int) bool { return shards[i].CompareTo(shards[j]) < 0 })
	sort.Slice(zones, func(i, j int) bool { return zones[i].CompareTo(zones[j]) < 0 })
	sort.Slice(queries, func(i, j int) bool { return queries[i].CompareTo(queries[j]) < 0 })
	sort.Slice(addressAssertions, func(i, j int) bool { return addressAssertions[i].CompareTo(addressAssertions[j]) < 0 })
	sort.Slice(addressZones, func(i, j int) bool { return addressZones[i].CompareTo(addressZones[j]) < 0 })
	sort.Slice(addressQueries, func(i, j int) bool { return addressQueries[i].CompareTo(addressQueries[j]) < 0 })
	sort.Slice(notifications, func(i, j int) bool { return notifications[i].CompareTo(notifications[j]) < 0 })
	m.Content = []MessageSection{}
	for _, section := range addressQueries {
		m.Content = append(m.Content, section)
	}
	for _, section := range addressZones {
		m.Content = append(m.Content, section)
	}
	for _, section := range addressAssertions {
		m.Content = append(m.Content, section)
	}
	for _, section := range assertions {
		m.Content = append(m.Content, section)
	}
	for _, section := range shards {
		m.Content = append(m.Content, section)
	}
	for _, section := range zones {
		m.Content = append(m.Content, section)
	}
	for _, section := range queries {
		m.Content = append(m.Content, section)
	}
	for _, section := range notifications {
		m.Content = append(m.Content, section)
	}
}

//Capability is a urn of a capability
type Capability string

const (
	//NoCapability is used when the server does not listen for any connections
	NoCapability Capability = "urn:x-rains:nocapability"
	//TLSOverTCP is used when the server listens for tls over tcp connections
	TLSOverTCP Capability = "urn:x-rains:tlssrv"
)

//Token identifies a message
type Token [16]byte

//String implements Stringer interface
func (t Token) String() string {
	return hex.EncodeToString(t[:])
}

//MessageSection can be either an Assertion, Shard, Zone, Query, Notification, AddressAssertion, AddressZone, AddressQuery section
type MessageSection interface {
	Sort()
	String() string
}

//MessageSectionWithSig is an interface for a section protected by a signature. In the current
//implementation it can be an Assertion, Shard, Zone, AddressAssertion, AddressZone
type MessageSectionWithSig interface {
	MessageSection
	AllSigs() []Signature
	Sigs(keyspace KeySpaceID) []Signature
	AddSig(sig Signature)
	DeleteSig(index int)
	GetContext() string
	GetSubjectZone() string
	UpdateValidity(validSince, validUntil int64, maxValidity time.Duration)
	ValidSince() int64
	ValidUntil() int64
	Hash() string
	IsConsistent() bool
	NeededKeys(map[SignatureMetaData]bool)
}

//MessageSectionWithSigForward can be either an Assertion, Shard or Zone
type MessageSectionWithSigForward interface {
	MessageSectionWithSig
	Interval
}

//MessageSectionQuery is the interface for a query section. In the current implementation it can be
//a query or an addressQuery
type MessageSectionQuery interface {
	GetContext() string
	GetExpiration() int64
}

//Interval defines an interval over strings
type Interval interface {
	//Begin of the interval
	Begin() string
	//End of the interval
	End() string
}

//Intersect returns true if a and b are overlapping
func Intersect(a, b Interval) bool {
	//case1: both intervals are points => compare with equality
	if a.Begin() == a.End() && b.Begin() == b.End() && a.Begin() != "" && b.Begin() != "" {
		return a.Begin() == b.Begin()
	}
	//case2: at least one of them is an interval
	if a.Begin() == "" {
		return b.Begin() == "" || a.End() == "" || a.End() > b.Begin()
	}
	if a.End() == "" {
		return b.End() == "" || a.Begin() < b.End()
	}
	if b.Begin() == "" {
		return b.End() == "" || b.End() > a.Begin()
	}
	if b.End() == "" {
		return b.Begin() < a.End()
	}
	return a.Begin() < b.End() && a.End() > b.Begin()
}

//TotalInterval is an interval over the whole namespace
type TotalInterval struct{}

//Begin defines the start of the total namespace
func (t TotalInterval) Begin() string {
	return ""
}

//End defines the end of the total namespace
func (t TotalInterval) End() string {
	return ""
}

//StringInterval implements Interval for a single string value
type StringInterval struct {
	Name string
}

//Begin defines the start of a StringInterval namespace
func (s StringInterval) Begin() string {
	return s.Name
}

//End defines the end of a StringInterval namespace
func (s StringInterval) End() string {
	return s.Name
}

//Hashable can be implemented by objects that are not natively hashable.
//For an object to be a map key (or a part thereof), it must be hashable.
type Hashable interface {
	//Hash must return a string uniquely identifying the object
	//It must hold for all objects that o1 == o2 iff o1.Hash() == o2.Hash()
	Hash() string
}

//SignatureMetaData contains meta data of the signature
type SignatureMetaData struct {
	PublicKeyID
	//ValidSince defines the time from which on this signature is valid. ValidSince is represented as seconds since the UNIX epoch UTC.
	ValidSince int64
	//ValidUntil defines the time after which this signature is not valid anymore. ValidUntil is represented as seconds since the UNIX epoch UTC.
	ValidUntil int64
}

func (sig SignatureMetaData) String() string {
	return fmt.Sprintf("%d %d %d %d %d",
		sig.KeySpace, sig.Algorithm, sig.ValidSince, sig.ValidUntil, sig.KeyPhase)
}

//Signature contains meta data of the signature and the signature data itself.
type Signature struct {
	PublicKeyID
	//ValidSince defines the time from which on this signature is valid. ValidSince is represented as seconds since the UNIX epoch UTC.
	ValidSince int64
	//ValidUntil defines the time after which this signature is not valid anymore. ValidUntil is represented as seconds since the UNIX epoch UTC.
	ValidUntil int64
	//Data holds the signature data
	Data interface{}
}

// UnmarshalArray takes in a CBOR decoded aray and populates Signature.
func (sig *Signature) UnmarshalArray(in []interface{}) error {
	if len(in) < 6 {
		return fmt.Errorf("expected at least 5 items in input array but got %d", len(in))
	}
	if in[0] != uint64(1) {
		return fmt.Errorf("only algorithm ED25519 is supported presently, but got: %d", in[0])
	}
	sig.PublicKeyID.Algorithm = Ed25519
	sig.PublicKeyID.KeyPhase = int(in[1].(uint64))
	sig.PublicKeyID.KeySpace = KeySpaceID(in[2].(uint64))
	sig.ValidSince = int64(in[3].(uint64))
	sig.ValidUntil = int64(in[4].(uint64))
	sig.Data = in[5]
	return nil
}

// MarshalCBOR implements a CBORMarshaler.
func (sig Signature) MarshalCBOR(w *borat.CBORWriter) error {
	// RAINS signatures have five common elements: the algorithm identifier, a
	// keyspace identifier, a keyphase identifier, a valid-since timestamp, and
	// a valid-until timestamp. Signatures are represented as an array of these
	// five values followed by additional elements containing the signature
	// data itself, according to the algorithm identifier.
	res := []interface{}{1, // FIXME: Hardcoded ED25519: there is no way to know what this is yet.
		int(sig.KeySpace), sig.KeyPhase, sig.ValidSince, sig.ValidUntil, sig.Data}
	return w.WriteArray(res)
}

//GetSignatureMetaData returns the signatures metaData
func (sig Signature) GetSignatureMetaData() SignatureMetaData {
	return SignatureMetaData{
		PublicKeyID: sig.PublicKeyID,
		ValidSince:  sig.ValidSince,
		ValidUntil:  sig.ValidUntil,
	}
}

//String implements Stringer interface
func (sig Signature) String() string {
	data := "notYetImplementedInStringMethod"
	if sig.Algorithm == Ed25519 {
		if sig.Data == nil {
			data = "nil"
		} else {
			data = hex.EncodeToString(sig.Data.([]byte))
		}
	}
	return fmt.Sprintf("{KS=%d AT=%d VS=%d VU=%d KP=%d data=%s}",
		sig.KeySpace, sig.Algorithm, sig.ValidSince, sig.ValidUntil, sig.KeyPhase, data)
}

//SignData adds signature meta data to encoding. It then signs the encoding with privateKey and updates sig.Data field with the generated signature
//In case of an error an error is returned indicating the cause, otherwise nil is returned
func (sig *Signature) SignData(privateKey interface{}, encoding string) error {
	if privateKey == nil {
		log.Warn("PrivateKey is nil")
		return errors.New("privateKey is nil")
	}
	encoding += sig.GetSignatureMetaData().String()
	data := []byte(encoding)
	switch sig.Algorithm {
	case Ed25519:
		if pkey, ok := privateKey.(ed25519.PrivateKey); ok {
			log.Debug("Sign data", "signature", sig, "privateKey", hex.EncodeToString(privateKey.(ed25519.PrivateKey)), "encoding", encoding)
			sig.Data = ed25519.Sign(pkey, data)
			return nil
		}
		log.Warn("Could not assert type ed25519.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
		return errors.New("could not assert type ed25519.PrivateKey")
	case Ed448:
		return errors.New("ed448 not yet supported in SignData()")
	case Ecdsa256:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha256.Sum256(data)
			r, s, err := ecdsa.Sign(rand.Reader, pkey, hash[:])
			if err != nil {
				log.Warn("Could not sign data", "error", err)
				return err
			}
			sig.Data = []*big.Int{r, s}
			return nil
		}
		log.Warn("Could not assert type ecdsa.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
		return errors.New("could not assert type ecdsa.PrivateKey")
	case Ecdsa384:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha512.Sum384(data)
			r, s, err := ecdsa.Sign(rand.Reader, pkey, hash[:])
			if err != nil {
				log.Warn("Could not sign data", "error", err)
				return err
			}
			sig.Data = []*big.Int{r, s}
			return nil
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
		return errors.New("could not assert type ecdsa.PrivateKey")
	default:
		log.Warn("Signature algorithm type not supported", "type", sig.Algorithm)
		return errors.New("signature algorithm type not supported")
	}
}

//VerifySignature adds signature meta data to the encoding. It then signs the encoding with privateKey and compares the resulting signature with the sig.Data.
//Returns true if there exist signatures and they are identical
func (sig *Signature) VerifySignature(publicKey interface{}, encoding string) bool {
	if sig.Data == nil {
		log.Warn("sig does not contain signature data", "sig", sig)
		return false
	}
	if publicKey == nil {
		log.Warn("PublicKey is nil")
		return false
	}
	encoding += sig.GetSignatureMetaData().String()
	data := []byte(encoding)
	switch sig.Algorithm {
	case Ed25519:
		if pkey, ok := publicKey.(ed25519.PublicKey); ok {
			return ed25519.Verify(pkey, data, sig.Data.([]byte))
		}
		log.Warn("Could not assert type ed25519.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	case Ed448:
		log.Warn("Ed448 not yet Supported!")
	case Ecdsa256:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := sig.Data.([]*big.Int); ok && len(sig) == 2 {
				hash := sha256.Sum256(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not assert type []*big.Int", "signatureDataType", fmt.Sprintf("%T", sig.Data))
			return false
		}
		log.Warn("Could not assert type ecdsa.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	case Ecdsa384:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := sig.Data.([]*big.Int); ok && len(sig) == 2 {
				hash := sha512.Sum384(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not assert type []*big.Int", "signature", sig.Data)
			return false
		}
		log.Warn("Could not assert type ecdsa.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	default:
		log.Warn("Signature algorithm type not supported", "type", sig.Algorithm)
	}
	return false
}

//NotificationType defines the type of a notification section
type NotificationType int

const (
	NTHeartbeat          NotificationType = 100
	NTCapHashNotKnown    NotificationType = 399
	NTBadMessage         NotificationType = 400
	NTRcvInconsistentMsg NotificationType = 403
	NTNoAssertionsExist  NotificationType = 404
	NTMsgTooLarge        NotificationType = 413
	NTUnspecServerErr    NotificationType = 500
	NTServerNotCapable   NotificationType = 501
	NTNoAssertionAvail   NotificationType = 504
)

//QueryOption enables a client or server to specify performance/privacy tradeoffs
type QueryOption int

const (
	QOMinE2ELatency            QueryOption = 1
	QOMinLastHopAnswerSize     QueryOption = 2
	QOMinInfoLeakage           QueryOption = 3
	QOCachedAnswersOnly        QueryOption = 4
	QOExpiredAssertionsOk      QueryOption = 5
	QOTokenTracing             QueryOption = 6
	QONoVerificationDelegation QueryOption = 7
	QONoProactiveCaching       QueryOption = 8
)

//ConnInfo contains address information about one actor of a connection of the declared type
type ConnInfo struct {
	//Type determines the network address type
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

//NetworkAndAddr returns the network name and addr of the connection separated by space
func (c ConnInfo) NetworkAndAddr() string {
	switch c.Type {
	case TCP:
		return fmt.Sprintf("%s %s", c.TCPAddr.Network(), c.String())
	default:
		log.Warn("Unsupported network address type", "type", c.Type)
		return ""
	}
}

//Hash returns a string containing all information uniquely identifying a ConnInfo.
func (c ConnInfo) Hash() string {
	return fmt.Sprintf("%v_%s", c.Type, c.String())
}

//Equal returns true if both Connection Information have the same existing type and the values corresponding to this type are identical.
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

//MaxCacheValidity defines the maximum duration each section containing signatures can be valid, starting from time.Now()
type MaxCacheValidity struct {
	AssertionValidity        time.Duration
	ShardValidity            time.Duration
	ZoneValidity             time.Duration
	AddressAssertionValidity time.Duration
	AddressZoneValidity      time.Duration
}

//RainsMsgParser can encode and decode RainsMessage.
//It is able to efficiently extract only the Token form an encoded RainsMessage
//It must always hold that: rainsMsg = Decode(Encode(rainsMsg)) && interface{} = Encode(Decode(interface{}))
type RainsMsgParser interface {
	//Decode extracts information from msg and returns a RainsMessage or an error
	Decode(msg []byte) (RainsMessage, error)

	//Encode encodes the given RainsMessage into a more compact representation.
	//If it was not able to encode msg an error is return indicating what the problem was.
	Encode(msg RainsMessage) ([]byte, error)

	//Token returns the extracted token from the given msg or an error
	Token(msg []byte) (Token, error)
}

//ZoneFileParser is the interface for all parsers of zone files for RAINS
type ZoneFileParser interface {
	//Decode takes as input a byte string of section(s) in zonefile format. It returns a slice of
	//all contained assertions, shards, and zones in the provided order or an error in case of
	//failure.
	Decode(zoneFile []byte) ([]MessageSectionWithSigForward, error)

	//DecodeZone takes as input a byte string of one zone in zonefile format. It returns the zone
	//exactly as it is in the zonefile or an error in case of failure.
	DecodeZone(zoneFile []byte) (*ZoneSection, error)

	//Encode returns the given section represented in zone file format if it is an assertion, shard,
	//or zone. In all other cases it returns the section in a displayable format similar to the zone
	//file format
	Encode(section MessageSection) string
}

//SignatureFormatEncoder is used to deterministically transform a RainsMessage or Section into a
//byte string that is ready for signing.
type SignatureFormatEncoder interface {
	//EncodeMessage transforms the given msg into a signable format.The signature meta data
	//must be present on the section. This method does not check for illegitimate content. The
	//returned byte string is ready for signing.
	EncodeMessage(msg *RainsMessage) []byte

	//EncodeSection transforms the given section into a signable format. The signature meta data
	//must be present on the section. This method does not check for illegitimate content. The
	//returned byte string is ready for signing.
	EncodeSection(section MessageSectionWithSig) []byte
}

//MsgFramer is used to frame and deframe rains messages and send or receive them on the initialized stream.
type MsgFramer interface {
	//InitStreams defines 2 streams.
	//Deframe() and Data() are extracting information from streamReader
	//Frame() is sending data to streamWriter.
	//If a stream is readable and writable it is possible that streamReader = streamWriter
	InitStreams(streamReader io.Reader, streamWriter io.Writer)

	//Frame encodes the msg and writes it to the streamWriter defined in InitStream()
	//The following must hold: DeFrame(Frame(msg)); Data() = msg
	//If Frame() was not able to frame or write the message an error is returned indicating what the problem was
	Frame(msg []byte) error

	//DeFrame extracts the next frame from the streamReader defined in InitStream().
	//It blocks until it encounters the end of the next frame.
	//It returns false when the stream was not initialized, an error occurred while reading or is already closed.
	//The data is available through Data
	DeFrame() bool

	//Data contains the frame read from the stream by DeFrame
	Data() []byte
}
