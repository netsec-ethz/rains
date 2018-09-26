package sections

import (
	"encoding/hex"
	"fmt"
	"go/token"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/types"
	"golang.org/x/crypto/ed25519"
)

//MessageSection can be either an Assertion, Shard, Zone, Query, Notification, AddressAssertion, AddressZone, AddressQuery section
type MessageSection interface {
	Sort()
	String() string
}

//MessageSectionWithSig is an interface for a section protected by a signature. In the current
//implementation it can be an Assertion, Shard, Zone, AddressAssertion, AddressZone
type MessageSectionWithSig interface {
	MessageSection
	AllSigs() []signature.Signature
	Sigs(keyspace keys.KeySpaceID) []signature.Signature
	AddSig(sig signature.Signature)
	DeleteSig(index int)
	GetContext() string
	GetSubjectZone() string
	UpdateValidity(validSince, validUntil int64, maxValidity time.Duration)
	ValidSince() int64
	ValidUntil() int64
	Hash() string
	IsConsistent() bool
	NeededKeys(map[signature.SignatureMetaData]bool)
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

//AssertionSection contains information about the assertion.
type AssertionSection struct {
	Signatures  []signature.Signature
	SubjectName string
	SubjectZone string
	Context     string
	Content     []object.Object
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

// UnmarshalMap provides functionality to unmarshal a map read in by CBOR.
func (a *AssertionSection) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0]; ok {
		a.Signatures = make([]signature.Signature, len(sigs.([]interface{})))
		for i, sig := range sigs.([]interface{}) {
			if err := a.Signatures[i].UnmarshalArray(sig.([]interface{})); err != nil {
				return err
			}
		}
	}
	if sn, ok := m[3]; ok {
		a.SubjectName = sn.(string)
	}
	if sz, ok := m[4]; ok {
		a.SubjectZone = sz.(string)
	}
	if ctx, ok := m[6]; ok {
		a.Context = ctx.(string)
	}
	if _, ok := m[7]; !ok {
		return fmt.Errorf("assertion does not contain any objects")
	}
	a.Content = make([]object.Object, 0)
	for _, obj := range m[7].([]interface{}) {
		objArr := obj.([]interface{})
		switch object.ObjectType(objArr[0].(uint64)) {
		case object.OTName:
			no := object.NameObject{Types: make([]object.ObjectType, 0)}
			no.Name = objArr[1].(string)
			for _, ot := range objArr[2].([]interface{}) {
				no.Types = append(no.Types, object.ObjectType(ot.(int)))
			}
			a.Content = append(a.Content, object.Object{Type: object.OTName, Value: no})
		case object.OTIP6Addr:
			ip := net.IP(objArr[1].([]byte))
			a.Content = append(a.Content, object.Object{Type: object.OTIP6Addr, Value: ip.String()})
		case object.OTIP4Addr:
			ip := net.IP(objArr[1].([]byte))
			a.Content = append(a.Content, object.Object{Type: object.OTIP4Addr, Value: ip.String()})
		case object.OTRedirection:
			a.Content = append(a.Content, object.Object{Type: object.OTRedirection, Value: objArr[1]})
		case object.OTDelegation:
			alg := objArr[1].(uint64)
			ks := keys.KeySpaceID(objArr[2].(uint64))
			kp := int(objArr[3].(uint64))
			vs := int64(objArr[4].(uint64))
			vu := int64(objArr[5].(uint64))
			var key interface{}
			switch algorithmTypes.SignatureAlgorithmType(alg) {
			case algorithmTypes.Ed25519:
				key = ed25519.PublicKey(objArr[6].([]byte))
			case algorithmTypes.Ecdsa256:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			case algorithmTypes.Ecdsa384:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			default:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			}
			pkey := keys.PublicKey{
				PublicKeyID: keys.PublicKeyID{
					Algorithm: algorithmTypes.SignatureAlgorithmType(alg),
					KeySpace:  ks,
					KeyPhase:  kp,
				},
				ValidSince: vs,
				ValidUntil: vu,
				Key:        key,
			}
			a.Content = append(a.Content, object.Object{Type: object.OTDelegation, Value: pkey})
		case object.OTNameset:
			a.Content = append(a.Content, object.Object{Type: object.OTNameset, Value: object.NamesetExpression(objArr[1].(string))})
		case object.OTCertInfo:
			co := object.CertificateObject{
				Type:     object.ProtocolType(objArr[1].(int)),
				Usage:    object.CertificateUsage(objArr[2].(int)),
				HashAlgo: algorithmTypes.HashAlgorithmType(objArr[3].(int)),
				Data:     objArr[4].([]byte),
			}
			a.Content = append(a.Content, object.Object{Type: object.OTCertInfo, Value: co})
		case object.OTServiceInfo:
			si := object.ServiceInfo{
				Name:     objArr[1].(string),
				Port:     uint16(objArr[2].(uint64)),
				Priority: uint(objArr[3].(uint64)),
			}
			a.Content = append(a.Content, object.Object{Type: object.OTServiceInfo, Value: si})
		case object.OTRegistrar:
			a.Content = append(a.Content, object.Object{Type: object.OTRegistrar, Value: objArr[2].(string)})
		case object.OTRegistrant:
			a.Content = append(a.Content, object.Object{Type: object.OTRegistrant, Value: objArr[2].(string)})
		case object.OTInfraKey:
			alg := objArr[1]
			ks := objArr[2].(keys.KeySpaceID)
			kp := objArr[3].(int)
			vs := objArr[4].(int64)
			vu := objArr[5].(int64)
			var key interface{}
			switch alg.(algorithmTypes.SignatureAlgorithmType) {
			case algorithmTypes.Ed25519:
				key = ed25519.PublicKey(objArr[6].([]byte))
			case algorithmTypes.Ecdsa256:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			case algorithmTypes.Ecdsa384:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			default:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			}
			pkey := keys.PublicKey{
				PublicKeyID: keys.PublicKeyID{
					Algorithm: alg.(algorithmTypes.SignatureAlgorithmType),
					KeySpace:  ks,
					KeyPhase:  kp,
				},
				ValidSince: vs,
				ValidUntil: vu,
				Key:        key,
			}
			a.Content = append(a.Content, object.Object{Type: object.OTInfraKey, Value: pkey})
		case object.OTExtraKey:
			alg := objArr[1].(algorithmTypes.SignatureAlgorithmType)
			ks := objArr[2].(keys.KeySpaceID)
			var key interface{}
			switch alg {
			case algorithmTypes.Ed25519:
				key = ed25519.PublicKey(objArr[3].([]byte))
			case algorithmTypes.Ecdsa256:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			case algorithmTypes.Ecdsa384:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			default:
				return fmt.Errorf("unsupported algorithm: %v", alg)
			}
			pk := keys.PublicKey{
				PublicKeyID: keys.PublicKeyID{
					Algorithm: alg,
					KeySpace:  ks,
				},
				Key: key,
			}
			a.Content = append(a.Content, object.Object{Type: object.OTExtraKey, Value: pk})
		case object.OTNextKey:
			// TODO: Implement OTNextKey.
		}
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (a *AssertionSection) MarshalCBOR(w *borat.CBORWriter) error {
	m := make(map[int]interface{})
	if len(a.Signatures) > 0 {
		m[0] = a.Signatures
	}
	if a.SubjectName != "" {
		m[3] = a.SubjectName
	}
	if a.SubjectZone != "" {
		m[4] = a.SubjectZone
	}
	if a.Context != "" {
		m[6] = a.Context
	}
	objs := make([][]interface{}, 0)
	for _, object := range a.Content {
		res, err := objectToArrayCBOR(object)
		if err != nil {
			return err
		}
		objs = append(objs, res)
	}
	m[7] = objs
	return w.WriteIntMap(m)
}

func objectToArrayCBOR(object object.Object) ([]interface{}, error) {
	var res []interface{}
	switch object.Type {
	case OTName:
		no, ok := object.Value.(NameObject)
		if !ok {
			return nil, fmt.Errorf("expected OTName to be NameObject but got: %T", object.Value)
		}
		ots := make([]int, len(no.Types))
		for i, ot := range no.Types {
			ots[i] = int(ot)
		}
		res = []interface{}{OTName, no.Name, ots}
	case OTIP6Addr:
		addrStr := object.Value.(string)
		addr := net.ParseIP(addrStr)
		res = []interface{}{OTIP6Addr, []byte(addr)}
	case OTIP4Addr:
		addrStr := object.Value.(string)
		addr := net.ParseIP(addrStr)
		res = []interface{}{OTIP4Addr, []byte(addr)}
	case OTRedirection:
		res = []interface{}{OTRedirection, object.Value}
	case OTDelegation:
		pkey, ok := object.Value.(PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", object.Value)
		}
		// TODO: ValidSince and ValidUntil should be tagged.
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTDelegation, int(pkey.Algorithm), int(pkey.KeySpace), pkey.KeyPhase, pkey.ValidSince, pkey.ValidUntil, b}
	case OTNameset:
		nse, ok := object.Value.(NamesetExpression)
		if !ok {
			return nil, fmt.Errorf("expected OTNameset value to be NamesetExpression but got: %T", object.Value)
		}
		res = []interface{}{OTNameset, string(nse)}
	case OTCertInfo:
		co, ok := object.Value.(CertificateObject)
		if !ok {
			return nil, fmt.Errorf("expected OTCertInfo object to be CertificateObject, but got: %T", object.Value)
		}
		res = []interface{}{OTCertInfo, int(co.Type), int(co.Usage), int(co.HashAlgo), co.Data}
	case OTServiceInfo:
		si, ok := object.Value.(ServiceInfo)
		if !ok {
			return nil, fmt.Errorf("expected OTServiceInfo object to be ServiceInfo, but got: %T", object.Value)
		}
		res = []interface{}{OTServiceInfo, si.Name, si.Port, si.Priority}
	case OTRegistrar:
		rstr, ok := object.Value.(string)
		if !ok {
			return nil, fmt.Errorf("expected OTRegistrar object to be string but got: %T", object.Value)
		}
		res = []interface{}{OTRegistrar, rstr}
	case OTRegistrant:
		rstr, ok := object.Value.(string)
		if !ok {
			return nil, fmt.Errorf("expected OTRegistrant object to be string but got: %T", object.Value)
		}
		res = []interface{}{OTRegistrant, rstr}
	case OTInfraKey:
		pkey, ok := object.Value.(PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", object.Value)
		}
		// TODO: ValidSince and ValidUntl should be tagged.
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTInfraKey, int(pkey.Algorithm), int(pkey.KeySpace), pkey.KeyPhase, pkey.ValidSince, pkey.ValidUntil, b}
	case OTExtraKey:
		pkey, ok := object.Value.(PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", object.Value)
		}
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTExtraKey, int(pkey.Algorithm), int(pkey.KeySpace), b}
	case OTNextKey:
	default:
		return nil, fmt.Errorf("unknown object type: %v", object.Type)
	}
	return res, nil
}

func pubkeyToCBORBytes(p keys.PublicKey) []byte {
	switch p.Algorithm {
	case Ed25519:
		return []byte(p.Key.(ed25519.PublicKey))
	case Ed448:
		panic("Unsupported algorithm.")
	case Ecdsa256:
		panic("Unsupported algorithm.")
	case Ecdsa384:
		panic("Unsupported algorithm.")
	default:
		panic("Unsupported algorithm.")
	}
}

//AllSigs returns all assertion's signatures
func (a *AssertionSection) AllSigs() []signature.Signature {
	return a.Signatures
}

//Sigs returns a's signatures in keyspace
func (a *AssertionSection) Sigs(keySpace keys.KeySpaceID) []signature.Signature {
	return filterSigs(a.Signatures, keySpace)
}

//AddSig adds the given signature
func (a *AssertionSection) AddSig(sig signature.Signature) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *AssertionSection) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//GetContext returns the context of the assertion
func (a *AssertionSection) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the zone of the assertion
func (a *AssertionSection) GetSubjectZone() string {
	return a.SubjectZone
}

//Copy creates a copy of the assertion with the given context and subjectZone values
func (a *AssertionSection) Copy(context, subjectZone string) *AssertionSection {
	stub := &AssertionSection{}
	*stub = *a
	stub.Context = context
	stub.SubjectZone = subjectZone
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
			a.validSince = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", a.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			a.validSince = validSince
		}
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", a.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
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
	if a == nil {
		return "A_nil"
	}
	return fmt.Sprintf("A_%s_%s_%s_%v_%v",
		a.SubjectName, a.SubjectZone, a.Context, a.Content, a.Signatures)
}

//EqualContextZoneName return true if the given assertion has the same context, subjectZone,
//subjectName.
func (a *AssertionSection) EqualContextZoneName(assertion *AssertionSection) bool {
	if assertion == nil {
		return false
	}
	return a.Context == assertion.Context &&
		a.SubjectZone == assertion.SubjectZone &&
		a.SubjectName == assertion.SubjectName
}

//Sort sorts the content of the assertion lexicographically.
func (a *AssertionSection) Sort() {
	for _, o := range a.Content {
		o.Sort()
	}
	sort.Slice(a.Content, func(i, j int) bool { return a.Content[i].CompareTo(a.Content[j]) < 0 })
}

//CompareTo compares two assertions and returns 0 if they are equal, 1 if a is greater than
//assertion and -1 if a is smaller than assertion
func (a *AssertionSection) CompareTo(assertion *AssertionSection) int {
	if a.SubjectName < assertion.SubjectName {
		return -1
	} else if a.SubjectName > assertion.SubjectName {
		return 1
	} else if a.SubjectZone < assertion.SubjectZone {
		return -1
	} else if a.SubjectZone > assertion.SubjectZone {
		return 1
	} else if a.Context < assertion.Context {
		return -1
	} else if a.Context > assertion.Context {
		return 1
	} else if len(a.Content) < len(assertion.Content) {
		return -1
	} else if len(a.Content) > len(assertion.Content) {
		return 1
	}
	for i, o := range a.Content {
		if o.CompareTo(assertion.Content[i]) != 0 {
			return o.CompareTo(assertion.Content[i])
		}
	}
	return 0
}

//String implements Stringer interface
func (a *AssertionSection) String() string {
	if a == nil {
		return "Assertion:nil"
	}
	return fmt.Sprintf("Assertion:[SN=%s SZ=%s CTX=%s CONTENT=%v SIG=%v]",
		a.SubjectName, a.SubjectZone, a.Context, a.Content, a.Signatures)
}

//IsConsistent returns true. Assertion is always consistent.
func (a *AssertionSection) IsConsistent() bool {
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all a's signatures.
func (a *AssertionSection) NeededKeys(keysNeeded map[signature.SignatureMetaData]bool) {
	extractNeededKeys(a, keysNeeded)
}

//extractNeededKeys adds all key metadata to sigData which are necessary to verify all section's
//signatures.
func extractNeededKeys(section MessageSectionWithSig, sigData map[signature.SignatureMetaData]bool) {
	for _, sig := range section.Sigs(RainsKeySpace) {
		sigData[sig.GetSignatureMetaData()] = true
	}
}

//BloomFilterEncoding returns a string encoding of the assertion to add to or query a bloom filter
func (a *AssertionSection) BloomFilterEncoding() string {
	return fmt.Sprintf("%s.%s %s %d", a.SubjectName, a.SubjectZone, a.Context, a.Content[0].Type)
}

//ShardSection contains information about the shard
type ShardSection struct {
	Signatures  []signature.Signature
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
	Content     []*AssertionSection
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

// UnmarshalMap converts a CBOR decoded map to this ShardSection.
func (s *ShardSection) UnmarshalMap(m map[int]interface{}) error {
	s.Signatures = make([]signature.Signature, 0)
	if sigs, ok := m[0]; ok {
		s.Signatures = make([]signature.Signature, len(sigs.([]interface{})))
		for i, sig := range sigs.([]interface{}) {
			if err := s.Signatures[i].UnmarshalArray(sig.([]interface{})); err != nil {
				return err
			}
		}
	}
	// SubjectZone
	if sz, ok := m[4]; ok {
		s.SubjectZone = sz.(string)
	}
	// Context
	if ctx, ok := m[6]; ok {
		s.Context = ctx.(string)
	}
	// RangeFrom/RangeTo
	if sr, ok := m[11]; ok {
		srange := sr.([]interface{})
		s.RangeFrom = srange[0].(string)
		s.RangeTo = srange[1].(string)
	}
	// Content
	if cont, ok := m[7]; ok {
		s.Content = make([]*AssertionSection, 0)
		for _, obj := range cont.([]interface{}) {
			as := &AssertionSection{}
			as.UnmarshalMap(obj.(map[int]interface{}))
			s.Content = append(s.Content, as)
		}
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (s *ShardSection) MarshalCBOR(w *borat.CBORWriter) error {
	fmt.Printf("Called MarshalCBOR on ShardSection")
	m := make(map[int]interface{})
	if len(s.Signatures) > 0 {
		m[0] = s.Signatures
	}
	if s.SubjectZone != "" {
		m[4] = s.SubjectZone
	}
	if s.Context != "" {
		m[6] = s.Context
	}
	m[11] = []string{s.RangeFrom, s.RangeTo}
	// TODO: Assertions SHOULD be sorted by name in ascending lexicographic order.
	m[7] = s.Content
	return w.WriteIntMap(m)
}

//AllSigs returns the shard's signatures
func (s *ShardSection) AllSigs() []signature.Signature {
	return s.Signatures
}

//Sigs returns s's signatures in keyspace
func (s *ShardSection) Sigs(keySpace keys.KeySpaceID) []signature.Signature {
	return filterSigs(s.Signatures, keySpace)
}

//AddSig adds the given signature
func (s *ShardSection) AddSig(sig signature.Signature) {
	s.Signatures = append(s.Signatures, sig)
}

//DeleteSig deletes ith signature
func (s *ShardSection) DeleteSig(i int) {
	s.Signatures = append(s.Signatures[:i], s.Signatures[i+1:]...)
}

//GetContext returns the context of the shard
func (s *ShardSection) GetContext() string {
	return s.Context
}

//GetSubjectZone returns the zone of the shard
func (s *ShardSection) GetSubjectZone() string {
	return s.SubjectZone
}

//Copy creates a copy of the shard with the given context and subjectZone values. The contained
//assertions are not modified
func (s *ShardSection) Copy(context, subjectZone string) *ShardSection {
	stub := &ShardSection{}
	*stub = *s
	stub.Context = context
	stub.SubjectZone = subjectZone
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
			s.validSince = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", s.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			s.validSince = validSince
		}
	}
	if validUntil > s.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			s.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", s.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
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
	if s == nil {
		return "S_nil"
	}
	aHashes := []string{}
	for _, a := range s.Content {
		aHashes = append(aHashes, a.Hash())
	}
	return fmt.Sprintf("S_%s_%s_%s_%s_[%s]_%v", s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo,
		strings.Join(aHashes, " "), s.Signatures)
}

//Sort sorts the content of the shard lexicographically.
func (s *ShardSection) Sort() {
	for _, a := range s.Content {
		a.Sort()
	}
	sort.Slice(s.Content, func(i, j int) bool { return s.Content[i].CompareTo(s.Content[j]) < 0 })
}

//CompareTo compares two shards and returns 0 if they are equal, 1 if s is greater than shard and -1
//if s is smaller than shard
func (s *ShardSection) CompareTo(shard *ShardSection) int {
	if s.SubjectZone < shard.SubjectZone {
		return -1
	} else if s.SubjectZone > shard.SubjectZone {
		return 1
	} else if s.Context < shard.Context {
		return -1
	} else if s.Context > shard.Context {
		return 1
	} else if s.RangeFrom < shard.RangeFrom {
		return -1
	} else if s.RangeFrom > shard.RangeFrom {
		return 1
	} else if s.RangeTo < shard.RangeTo {
		return -1
	} else if s.RangeTo > shard.RangeTo {
		return 1
	} else if len(s.Content) < len(shard.Content) {
		return -1
	} else if len(s.Content) > len(shard.Content) {
		return 1
	}
	for i, a := range s.Content {
		if a.CompareTo(shard.Content[i]) != 0 {
			return a.CompareTo(shard.Content[i])
		}
	}
	return 0
}

//String implements Stringer interface
func (s *ShardSection) String() string {
	if s == nil {
		return "Shard:nil"
	}
	return fmt.Sprintf("Shard:[SZ=%s CTX=%s RF=%s RT=%s CONTENT=%v SIG=%v]",
		s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo, s.Content, s.Signatures)
}

//AssertionsByNameAndTypes returns all contained assertions with subjectName and at least one object
//that has a type contained in types. It is assumed that the contained assertions are sorted by
//subjectName in ascending order. The returned assertions are pairwise distinct.
func (s *ShardSection) AssertionsByNameAndTypes(subjectName string, types []object.ObjectType) []*AssertionSection {
	assertionMap := make(map[string]*AssertionSection)
	i := sort.Search(len(s.Content), func(i int) bool { return s.Content[i].SubjectName >= subjectName })
	for ; i < len(s.Content) && s.Content[i].SubjectName == subjectName; i++ {
		for _, oType := range types {
			if _, ok := ContainsType(s.Content[i].Content, oType); ok {
				assertionMap[s.Content[i].Hash()] = s.Content[i]
				break
			}
		}
	}
	var assertions []*AssertionSection
	for _, a := range assertionMap {
		assertions = append(assertions, a)
	}
	return assertions
}

//InRange returns true if subjectName is inside the shard range
func (s *ShardSection) InRange(subjectName string) bool {
	return (s.RangeFrom == "" && s.RangeTo == "") || (s.RangeFrom == "" && s.RangeTo > subjectName) ||
		(s.RangeTo == "" && s.RangeFrom < subjectName) ||
		(s.RangeFrom < subjectName && s.RangeTo > subjectName)
}

//AddZoneAndContextToAssertions adds the shard's subjectZone and context value to all contained
//assertions
func (s *ShardSection) AddZoneAndContextToAssertions() {
	for _, a := range s.Content {
		a.SubjectZone = s.SubjectZone
		a.Context = s.Context
	}
}

//IsConsistent returns true if all contained assertions have no subjectZone and context and are
//within the shards range.
func (s *ShardSection) IsConsistent() bool {
	for _, a := range s.Content {
		if sectionHasContextOrSubjectZone(a) {
			log.Warn("Contained assertion has a subjectZone or context", "assertion", a)
			return false
		}
		if !s.InRange(a.SubjectName) {
			log.Warn("Contained assertion's subjectName is outside the shard's range", "subjectName",
				a.SubjectName, "Range", fmt.Sprintf("[%s:%s]", s.RangeFrom, s.RangeTo))
			return false
		}
	}
	return true
}

//sectionHasContextOrSubjectZone returns false if the section's subjectZone and context are both the
//empty string
func sectionHasContextOrSubjectZone(section MessageSectionWithSig) bool {
	return section.GetSubjectZone() != "" || section.GetContext() != ""
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all s's signatures.
func (s *ShardSection) NeededKeys(keysNeeded map[signature.SignatureMetaData]bool) {
	extractNeededKeys(s, keysNeeded)
	for _, a := range s.Content {
		a.NeededKeys(keysNeeded)
	}
}

//Pshard contains information about a pshard
type PshardSection struct {
	Signatures    []signature.Signature
	SubjectZone   string
	Context       string
	RangeFrom     string
	RangeTo       string
	Datastructure DataStructure
	validSince    int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil    int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//AllSigs returns the pshard's signatures
func (s *PshardSection) AllSigs() []signature.Signature {
	return s.Signatures
}

//Sigs returns s's signatures in keyspace
func (s *PshardSection) Sigs(keySpace keys.KeySpaceID) []signature.Signature {
	return filterSigs(s.Signatures, keySpace)
}

//AddSig adds the given signature
func (s *PshardSection) AddSig(sig signature.Signature) {
	s.Signatures = append(s.Signatures, sig)
}

//DeleteSig deletes ith signature
func (s *PshardSection) DeleteSig(i int) {
	s.Signatures = append(s.Signatures[:i], s.Signatures[i+1:]...)
}

//GetContext returns the context of the pshard
func (s *PshardSection) GetContext() string {
	return s.Context
}

//GetSubjectZone returns the zone of the pshard
func (s *PshardSection) GetSubjectZone() string {
	return s.SubjectZone
}

//Begin returns the begining of the interval of this pshard.
func (s *PshardSection) Begin() string {
	return s.RangeFrom
}

//End returns the end of the interval of this pshard.
func (s *PshardSection) End() string {
	return s.RangeTo
}

//UpdateValidity updates the validity of this pshard if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (s *PshardSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if s.validSince == 0 {
		s.validSince = math.MaxInt64
	}
	if validSince < s.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			s.validSince = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", s.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			s.validSince = validSince
		}
	}
	if validUntil > s.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			s.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", s.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			s.validUntil = validUntil
		}
	}
}

//ValidSince returns the earliest validSince date of all contained signatures
func (s *PshardSection) ValidSince() int64 {
	return s.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (s *PshardSection) ValidUntil() int64 {
	return s.validUntil
}

//Hash returns a string containing all information uniquely identifying a pshard.
func (s *PshardSection) Hash() string {
	if s == nil {
		return "S_nil"
	}
	return fmt.Sprintf("S_%s_%s_%s_%s_%v_%v", s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo,
		s.Datastructure, s.Signatures)
}

//Sort sorts the content of the pshard lexicographically.
func (s *PshardSection) Sort() {
	//nothing to sort
}

//CompareTo compares two shards and returns 0 if they are equal, 1 if s is greater than shard and -1
//if s is smaller than shard
func (s *PshardSection) CompareTo(shard *PshardSection) int {
	if s.SubjectZone < shard.SubjectZone {
		return -1
	} else if s.SubjectZone > shard.SubjectZone {
		return 1
	} else if s.Context < shard.Context {
		return -1
	} else if s.Context > shard.Context {
		return 1
	} else if s.RangeFrom < shard.RangeFrom {
		return -1
	} else if s.RangeFrom > shard.RangeFrom {
		return 1
	} else if s.RangeTo < shard.RangeTo {
		return -1
	} else if s.RangeTo > shard.RangeTo {
		return 1
	}
	//FIXME CFE compare datastructure
	return 0
}

//String implements Stringer interface
func (s *PshardSection) String() string {
	if s == nil {
		return "Shard:nil"
	}
	return fmt.Sprintf("Shard:[SZ=%s CTX=%s RF=%s RT=%s DS=%v SIG=%v]",
		s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo, s.Datastructure, s.Signatures)
}

//InRange returns true if subjectName is inside the shard range
func (s *PshardSection) InRange(subjectName string) bool {
	return (s.RangeFrom == "" && s.RangeTo == "") || (s.RangeFrom == "" && s.RangeTo > subjectName) ||
		(s.RangeTo == "" && s.RangeFrom < subjectName) ||
		(s.RangeFrom < subjectName && s.RangeTo > subjectName)
}

//IsConsistent returns true if all contained assertions have no subjectZone and context and are
//within the shards range.
func (s *PshardSection) IsConsistent() bool {
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all s's signatures.
func (s *PshardSection) NeededKeys(keysNeeded map[signature.SignatureMetaData]bool) {
	extractNeededKeys(s, keysNeeded)
}

//ZoneSection contains information about the zone
type ZoneSection struct {
	Signatures  []signature.Signature
	SubjectZone string
	Context     string
	Content     []MessageSectionWithSigForward
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (z *ZoneSection) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0]; ok {
		z.Signatures = make([]Signature, len(sigs.([]interface{})))
		for i, sig := range sigs.([]interface{}) {
			if err := z.Signatures[i].UnmarshalArray(sig.([]interface{})); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("missing signatures from ZoneSection")
	}
	if sz, ok := m[4]; ok {
		z.SubjectZone = sz.(string)
	} else {
		return fmt.Errorf("missing SubjectZone from ZoneSection")
	}
	if ctx, ok := m[6]; ok {
		z.Context = ctx.(string)
	} else {
		return fmt.Errorf("missing Context from ZoneSection")
	}
	// Content is an array of ShardSections and / or AssertionSections.
	if content, ok := m[23]; ok {
		z.Content = make([]MessageSectionWithSigForward, 0)
		for _, item := range content.([]interface{}) {
			m := item.(map[int]interface{})
			if _, ok := m[11]; ok {
				// ShardSection.
				ss := &ShardSection{}
				if err := ss.UnmarshalMap(m); err != nil {
					return fmt.Errorf("failed to unmarshal ShardSection map in ZoneSection: %v", err)
				}
				z.Content = append(z.Content, ss)
			} else {
				// AssertionSection.
				as := &AssertionSection{}
				if err := as.UnmarshalMap(m); err != nil {
					return fmt.Errorf("failed to unmarshal AssertionSection map in ZoneSection: %v", err)
				}
				z.Content = append(z.Content, as)
			}
		}
	} else {
		return fmt.Errorf("missing content for ZoneSection")
	}
	return nil
}

func (z *ZoneSection) MarshalCBOR(w *borat.CBORWriter) error {
	m := make(map[int]interface{})
	m[23] = z.Content
	m[0] = z.Signatures
	m[4] = z.SubjectZone
	m[6] = z.Context
	return w.WriteIntMap(m)
}

//AllSigs returns the zone's signatures
func (z *ZoneSection) AllSigs() []signature.Signature {
	return z.Signatures
}

//Sigs returns z's signatures in keyspace
func (z *ZoneSection) Sigs(keySpace keys.KeySpaceID) []signature.Signature {
	return filterSigs(z.Signatures, keySpace)
}

//AddSig adds the given signature
func (z *ZoneSection) AddSig(sig signature.Signature) {
	z.Signatures = append(z.Signatures, sig)
}

//DeleteSig deletes ith signature
func (z *ZoneSection) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//GetContext returns the context of the zone
func (z *ZoneSection) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the zone of the zone
func (z *ZoneSection) GetSubjectZone() string {
	return z.SubjectZone
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
			z.validSince = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", z.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			z.validSince = validSince
		}
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", z.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
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
	if z == nil {
		return "Z_nil"
	}
	contentHashes := []string{}
	for _, v := range z.Content {
		switch v := v.(type) {
		case *AssertionSection, *ShardSection:
			contentHashes = append(contentHashes, v.Hash())
		default:
			log.Warn(fmt.Sprintf("not supported zone section content, must be assertion or shard, got %T", v))
			return ""
		}
	}
	return fmt.Sprintf("Z_%s_%s_[%s]_%v", z.SubjectZone, z.Context, strings.Join(contentHashes, " "),
		z.Signatures)
}

//Sort sorts the content of the zone lexicographically.
func (z *ZoneSection) Sort() {
	for _, s := range z.Content {
		s.Sort()
	}
	sort.Slice(z.Content, func(i, j int) bool {
		switch section := z.Content[i].(type) {
		case *AssertionSection:
			if a, ok := z.Content[j].(*AssertionSection); ok {
				return section.CompareTo(a) < 0
			}
			return true
		case *PshardSection:
			if s, ok := z.Content[j].(*PshardSection); ok {
				return section.CompareTo(s) < 0
			}
			if _, ok := z.Content[j].(*AssertionSection); ok {
				return false
			}
			return true //it is a shard
		case *ShardSection:
			if s, ok := z.Content[j].(*ShardSection); ok {
				return section.CompareTo(s) < 0
			}
			return false
		default:
			log.Error(fmt.Sprintf("Unexpected element contained in zone: got Type=%T", z.Content[i]))
			return false
		}
	})
}

//CompareTo compares two zones and returns 0 if they are equal, 1 if z is greater than zone and -1
//if z is smaller than zone
func (z *ZoneSection) CompareTo(zone *ZoneSection) int {
	if z.SubjectZone < zone.SubjectZone {
		return -1
	} else if z.SubjectZone > zone.SubjectZone {
		return 1
	} else if z.Context < zone.Context {
		return -1
	} else if z.Context > zone.Context {
		return 1
	} else if len(z.Content) < len(zone.Content) {
		return -1
	} else if len(z.Content) > len(zone.Content) {
		return 1
	}
	for i, section := range z.Content {
		switch section := section.(type) {
		case *AssertionSection:
			if a, ok := zone.Content[i].(*AssertionSection); ok {
				if section.CompareTo(a) != 0 {
					return section.CompareTo(a)
				}
			} else {
				return -1
			}
		case *ShardSection:
			if s, ok := zone.Content[i].(*ShardSection); ok {
				if section.CompareTo(s) != 0 {
					return section.CompareTo(s)
				}
			} else {
				return 1
			}
		default:
			log.Error(fmt.Sprintf("Unexpected element contained in zone: got Type=%T", z.Content[i]))
		}
	}
	return 0
}

//String implements Stringer interface
func (z *ZoneSection) String() string {
	if z == nil {
		return "Zone:nil"
	}
	return fmt.Sprintf("Zone:[SZ=%s CTX=%s CONTENT=%v SIG=%v]",
		z.SubjectZone, z.Context, z.Content, z.Signatures)
}

//SectionsByNameAndTypes returns all contained assertions with subjectName and at least one object
//that has a type contained in types together with all contained shards having subjectName in their
//range. It is assumed that the contained sections are sorted as for signing. The returned
//assertions and shards are pairwise distinct.
func (z *ZoneSection) SectionsByNameAndTypes(subjectName string, types []object.ObjectType) (
	[]*AssertionSection, []*ShardSection) {
	assertionMap := make(map[string]*AssertionSection)
	shardMap := make(map[string]*ShardSection)

	//extract assertions matching subjectName
	i := sort.Search(len(z.Content), func(i int) bool {
		if a, ok := z.Content[i].(*AssertionSection); ok {
			return a.SubjectName >= subjectName
		}
		return true
	})
	for ; i < len(z.Content); i++ {
		if a, ok := z.Content[i].(*AssertionSection); ok && a.SubjectName == subjectName {
			for _, oType := range types {
				if _, ok := ContainsType(a.Content, oType); ok {
					assertionMap[a.Hash()] = a
					break
				}
			}
		} else {
			break
		}
	}

	//extract assertions contained in shards matching subjectName and shards having subjectName in
	//their range.
	i = sort.Search(len(z.Content), func(i int) bool {
		_, ok := z.Content[i].(*ShardSection)
		return ok
	})
	for ; i < len(z.Content); i++ {
		if s, ok := z.Content[i].(*ShardSection); ok && s.RangeFrom < subjectName {
			if s.RangeTo == "" || s.RangeTo > subjectName {
				shardMap[s.Hash()] = s
				answers := s.AssertionsByNameAndTypes(subjectName, types)
				for _, a := range answers {
					assertionMap[a.Hash()] = a
				}
			}
		} else {
			break
		}
	}

	var assertions []*AssertionSection
	for _, a := range assertionMap {
		assertions = append(assertions, a)
	}
	var shards []*ShardSection
	for _, s := range shardMap {
		shards = append(shards, s)
	}
	return assertions, shards
}

//AddZoneAndContextToSections adds the zone's subjectZone and context value to all contained
//assertions and shards
func (z *ZoneSection) AddZoneAndContextToSections() {
	for _, sec := range z.Content {
		switch sec := sec.(type) {
		case *AssertionSection:
			sec.SubjectZone = z.SubjectZone
			sec.Context = z.Context
		case *ShardSection:
			sec.SubjectZone = z.SubjectZone
			sec.Context = z.Context
			for _, a := range sec.Content {
				a.SubjectZone = z.SubjectZone
				a.Context = z.Context
			}
		default:
			log.Warn("Not supported message section inside zone")
		}
	}
}

//IsConsistent returns true if all contained assertions and shards are consistent
func (z *ZoneSection) IsConsistent() bool {
	for _, section := range z.Content {
		if sectionHasContextOrSubjectZone(section) {
			log.Warn("Contained section has a subjectZone or context", "section", section)
			return false
		}
		if shard := section.(*ShardSection); !shard.IsConsistent() {
			return false //already logged
		}
	}
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all z's signatures.
func (z *ZoneSection) NeededKeys(keysNeeded map[signature.SignatureMetaData]bool) {
	extractNeededKeys(z, keysNeeded)
	for _, section := range z.Content {
		section.NeededKeys(keysNeeded)
	}
}

//QuerySection contains information about the query
type QuerySection struct {
	Context    string
	Name       string
	Types      []object.ObjectType
	Expiration int64 //unix seconds
	Options    []QueryOption
}

// UnmarshalMap unpacks a CBOR marshaled map to this struct.
func (q *QuerySection) UnmarshalMap(m map[int]interface{}) error {
	q.Name = m[8].(string)
	q.Context = m[6].(string)
	q.Types = make([]object.ObjectType, 0)
	if types, ok := m[10]; ok {
		for _, qt := range types.([]interface{}) {
			q.Types = append(q.Types, object.ObjectType(qt.(uint64)))
		}
	}
	q.Expiration = int64(m[12].(uint64))
	q.Options = make([]QueryOption, 0)
	if opts, ok := m[13]; ok {
		for _, opt := range opts.([]interface{}) {
			q.Options = append(q.Options, QueryOption(opt.(uint64)))
		}
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (q *QuerySection) MarshalCBOR(w *borat.CBORWriter) error {
	m := make(map[int]interface{})
	m[8] = q.Name
	m[6] = q.Context
	qtypes := make([]int, len(q.Types))
	for i, qtype := range q.Types {
		qtypes[i] = int(qtype)
	}
	m[10] = qtypes
	m[12] = q.Expiration
	qopts := make([]int, len(q.Options))
	for i, qopt := range q.Options {
		qopts[i] = int(qopt)
	}
	m[13] = qopts
	return w.WriteIntMap(m)
}

//GetContext returns q's context
func (q *QuerySection) GetContext() string {
	return q.Context
}

//GetExpiration returns q's expiration
func (q *QuerySection) GetExpiration() int64 {
	return q.Expiration
}

//ContainsOption returns true if the query contains the given query option.
func (q *QuerySection) ContainsOption(option QueryOption) bool {
	return containsOption(option, q.Options)
}

//containsOption return true if option is contained in options
func containsOption(option QueryOption, options []QueryOption) bool {
	for _, opt := range options {
		if opt == option {
			return true
		}
	}
	return false
}

//Sort sorts the content of the query lexicographically.
func (q *QuerySection) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two queries and returns 0 if they are equal, 1 if q is greater than query and
//-1 if q is smaller than query
func (q *QuerySection) CompareTo(query *QuerySection) int {
	if q.Context < query.Context {
		return -1
	} else if q.Context > query.Context {
		return 1
	} else if q.Name < query.Name {
		return -1
	} else if q.Name > query.Name {
		return 1
	} else if len(q.Types) < len(query.Types) {
		return -1
	} else if len(q.Types) > len(query.Types) {
		return 1
	}
	for i, o := range q.Types {
		if o < query.Types[i] {
			return -1
		} else if o > query.Types[i] {
			return 1
		}
	}
	if q.Expiration < query.Expiration {
		return -1
	} else if q.Expiration > query.Expiration {
		return 1
	} else if len(q.Options) < len(query.Options) {
		return -1
	} else if len(q.Options) > len(query.Options) {
		return 1
	}
	for i, o := range q.Options {
		if o < query.Options[i] {
			return -1
		} else if o > query.Options[i] {
			return 1
		}
	}
	return 0
}

//String implements Stringer interface
func (q *QuerySection) String() string {
	if q == nil {
		return "Query:nil"
	}
	return fmt.Sprintf("Query:[CTX=%s NA=%s TYPE=%v EXP=%d OPT=%v]",
		q.Context, q.Name, q.Types, q.Expiration, q.Options)
}

type AssertionUpdateSection struct {
	Name       string
	HashType   algorithmTypes.HashAlgorithmType
	HashValue  []byte
	Expiration int64 //unix seconds
	Options    []QueryOption
}

//String implements Stringer interface
func (q *AssertionUpdateSection) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[NA=%s HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Name, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration, q.Options)
}

type NonExistenceUpdateSection struct {
	Context     string
	Name        string
	ObjectTypes []object.ObjectType
	HashType    algorithmTypes.HashAlgorithmType
	HashValue   []byte
	Expiration  int64 //unix seconds
	Options     []QueryOption
}

//String implements Stringer interface
func (q *NonExistenceUpdateSection) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[CTX=%s NA=%s OTYPE=%v HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Context, q.Name, q.ObjectTypes, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration,
		q.Options)
}

//AddressAssertionSection contains information about the address assertion
type AddressAssertionSection struct {
	Signatures  []signature.Signature
	SubjectAddr *net.IPNet
	Context     string
	Content     []object.Object
	validSince  int64
	validUntil  int64
}

// MarshalCBOR implements the CBORMarshaler interface.
func (a *AddressAssertionSection) MarshalCBOR(w *borat.CBORWriter) error {
	m := make(map[int]interface{})
	m[0] = a.Signatures
	var af int
	subAddr := a.SubjectAddr
	if subAddr.IP.To4() == nil {
		af = 2 // for IPv6 address.
	} else {
		af = 3 // for IPv4 address.
	}
	_, plen := subAddr.Mask.Size()
	sa := []interface{}{af, plen, []byte(subAddr.IP)}
	m[5] = sa
	if a.Context != "" {
		m[6] = a.Context
	}
	objs := make([][]interface{}, 0)
	for _, object := range a.Content {
		res, err := objectToArrayCBOR(object)
		if err != nil {
			return err
		}
		objs = append(objs, res)
	}
	m[7] = objs
	return w.WriteIntMap(m)
}

//AllSigs return the assertion's signatures
func (a *AddressAssertionSection) AllSigs() []signature.Signature {
	return a.Signatures
}

//Sigs returns a's signatures in keyspace
func (a *AddressAssertionSection) Sigs(keySpace keys.KeySpaceID) []signature.Signature {
	return filterSigs(a.Signatures, keySpace)
}

//AddSig adds the given signature
func (a *AddressAssertionSection) AddSig(sig signature.Signature) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *AddressAssertionSection) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//GetContext returns the context of the assertion
func (a *AddressAssertionSection) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the SubjectAddr
func (a *AddressAssertionSection) GetSubjectZone() string {
	return a.SubjectAddr.String()
}

//UpdateValidity updates the validity of this assertion if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (a *AddressAssertionSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if a.validSince == 0 {
		a.validSince = math.MaxInt64
	}
	if validSince < a.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			a.validSince = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", a.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)

		} else {
			a.validSince = validSince
		}
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", a.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
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
	if a == nil {
		return "AA_nil"
	}
	return fmt.Sprintf("AA_%s_%s_%v_%v",
		a.SubjectAddr,
		a.Context,
		a.Content,
		a.Signatures)
}

//Sort sorts the content of the addressAssertion lexicographically.
func (a *AddressAssertionSection) Sort() {
	for _, o := range a.Content {
		o.Sort()
	}
	sort.Slice(a.Content, func(i, j int) bool { return a.Content[i].CompareTo(a.Content[j]) < 0 })
}

//CompareTo compares two addressAssertions and returns 0 if they are equal, 1 if a is greater than
//assertion and -1 if a is smaller than assertion
func (a *AddressAssertionSection) CompareTo(assertion *AddressAssertionSection) int {
	if a.SubjectAddr.String() < assertion.SubjectAddr.String() {
		return -1
	} else if a.SubjectAddr.String() > assertion.SubjectAddr.String() {
		return 1
	} else if a.Context < assertion.Context {
		return -1
	} else if a.Context > assertion.Context {
		return 1
	} else if len(a.Content) < len(assertion.Content) {
		return -1
	} else if len(a.Content) > len(assertion.Content) {
		return 1
	}
	for i, o := range a.Content {
		if o.CompareTo(assertion.Content[i]) != 0 {
			return o.CompareTo(assertion.Content[i])
		}
	}
	return 0
}

//String implements Stringer interface
func (a *AddressAssertionSection) String() string {
	if a == nil {
		return "AddressAssertion:nil"
	}
	return fmt.Sprintf("AddressAssertion:[SA=%s CTX=%s CONTENT=%v SIG=%v]",
		a.SubjectAddr, a.Context, a.Content, a.Signatures)
}

//IsConsistent returns false if the addressAssertion contains not allowed object types
func (a *AddressAssertionSection) IsConsistent() bool {
	for _, o := range a.Content {
		if invalidObjectType(a.SubjectAddr, o.Type) {
			log.Warn("Not allowed object type for an address assertion.", "objectType", o.Type,
				"subjectAddr", a.SubjectAddr)
			return false
		}
	}
	return true
}

//invalidObjectType returns true if the object type is not allowed for the given subjectAddr.
func invalidObjectType(subjectAddr *net.IPNet, objectType object.ObjectType) bool {
	prefixLength, addressLength := subjectAddr.Mask.Size()
	if addressLength == 32 {
		if prefixLength == 32 {
			return objectType != OTName
		}
		return objectType != OTDelegation && objectType != OTRedirection && objectType != OTRegistrant
	}
	if addressLength == 128 {
		if prefixLength == 128 {
			return objectType != OTName
		}
		return objectType != OTDelegation && objectType != OTRedirection && objectType != OTRegistrant
	}
	log.Warn("Invalid addressLength", "addressLength", addressLength)
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all a's signatures.
func (a *AddressAssertionSection) NeededKeys(keysNeeded map[signature.SignatureMetaData]bool) {
	extractNeededKeys(a, keysNeeded)
}

//AddressZoneSection contains information about the address zone
type AddressZoneSection struct {
	Signatures  []signature.Signature
	SubjectAddr *net.IPNet
	Context     string
	Content     []*AddressAssertionSection
	validSince  int64
	validUntil  int64
}

//AllSigs return the zone's signatures
func (z *AddressZoneSection) AllSigs() []signature.Signature {
	return z.Signatures
}

//Sigs returns z's signatures in keyspace
func (z *AddressZoneSection) Sigs(keySpace keys.KeySpaceID) []signature.Signature {
	return filterSigs(z.Signatures, keySpace)
}

//AddSig adds the given signature
func (z *AddressZoneSection) AddSig(sig signature.Signature) {
	z.Signatures = append(z.Signatures, sig)
}

//DeleteSig deletes ith signature
func (z *AddressZoneSection) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//GetContext returns the context of the zone
func (z *AddressZoneSection) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the SubjectAddr of the zone
func (z *AddressZoneSection) GetSubjectZone() string {
	return z.SubjectAddr.String()
}

//UpdateValidity updates the validity of this addressZone if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (z *AddressZoneSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if z.validSince == 0 {
		z.validSince = math.MaxInt64
	}
	if validSince < z.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			z.validSince = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", z.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			z.validSince = validSince
		}
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", z.validSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
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
	if z == nil {
		return "AZ_nil"
	}
	contentHashes := []string{}
	for _, a := range z.Content {
		contentHashes = append(contentHashes, a.Hash())
	}
	return fmt.Sprintf("AZ_%s_%s_[%s]_%v",
		z.SubjectAddr,
		z.Context,
		strings.Join(contentHashes, " "),
		z.Signatures)
}

//Sort sorts the content of the addressZone lexicographically.
func (z *AddressZoneSection) Sort() {
	for _, a := range z.Content {
		a.Sort()
	}
	sort.Slice(z.Content, func(i, j int) bool { return z.Content[i].CompareTo(z.Content[j]) < 0 })
}

//CompareTo compares two addressZones and returns 0 if they are equal, 1 if z is greater than zone
//and -1 if z is smaller than zone
func (z *AddressZoneSection) CompareTo(zone *AddressZoneSection) int {
	if z.SubjectAddr.String() < zone.SubjectAddr.String() {
		return -1
	} else if z.SubjectAddr.String() > zone.SubjectAddr.String() {
		return 1
	} else if z.Context < zone.Context {
		return -1
	} else if z.Context > zone.Context {
		return 1
	} else if len(z.Content) < len(zone.Content) {
		return -1
	} else if len(z.Content) > len(zone.Content) {
		return 1
	}
	for i, a := range z.Content {
		if a.CompareTo(zone.Content[i]) != 0 {
			return a.CompareTo(zone.Content[i])
		}
	}
	return 0
}

//String implements Stringer interface
func (z *AddressZoneSection) String() string {
	if z == nil {
		return "AddressZone:nil"
	}
	return fmt.Sprintf("AddressZone:[SA=%s CTX=%s CONTENT=%v SIG=%v]",
		z.SubjectAddr, z.Context, z.Content, z.Signatures)
}

//IsConsistent returns true if all contained addressAssertions are consistent and within the
//addressZone's subjectAddr
func (z *AddressZoneSection) IsConsistent() bool {
	//if addressZone needed use this function assertionAddrWithinZoneAddr()
	log.Error("TODO CFE implement it if necessary")
	return true
}

//assertionAddrWithinZoneAddr returns true if the assertion's subjectAddress is within the outer
//zone's subjectAddress
func assertionAddrWithinZoneAddr(assertionSubjectAddr, zoneSubejectAddr *net.IPNet) bool {
	zprefix, _ := zoneSubejectAddr.Mask.Size()
	aprefix, _ := assertionSubjectAddr.Mask.Size()
	if aprefix < zprefix {
		log.Warn("Assertion is less specific than zone", "assertion prefix", aprefix,
			"zone prefix", zprefix)
		return false
	}
	if !zoneSubejectAddr.Contains(assertionSubjectAddr.IP) {
		log.Warn("Assertion network is not contained in zone network",
			"assertion network", assertionSubjectAddr, "zone network", zoneSubejectAddr)
		return false
	}
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all z's signatures.
func (z *AddressZoneSection) NeededKeys(keysNeeded map[signature.SignatureMetaData]bool) {
	extractNeededKeys(z, keysNeeded)
	for _, a := range z.Content {
		a.NeededKeys(keysNeeded)
	}
}

//AddressQuerySection contains information about the address query
type AddressQuerySection struct {
	SubjectAddr *net.IPNet
	Context     string
	Types       []object.ObjectType
	Expiration  int64 //Unix seconds
	Options     []QueryOption
}

//GetContext returns q's context
func (q *AddressQuerySection) GetContext() string {
	return q.Context
}

//GetExpiration returns q's expiration
func (q *AddressQuerySection) GetExpiration() int64 {
	return q.Expiration
}

//ContainsOption returns true if the address query contains the given query option.
func (q *AddressQuerySection) ContainsOption(option QueryOption) bool {
	return containsOption(option, q.Options)
}

//Sort sorts the content of the addressQuery lexicographically.
func (q *AddressQuerySection) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two addressQueries and returns 0 if they are equal, 1 if q is greater than
//query and -1 if q is smaller than query
func (q *AddressQuerySection) CompareTo(query *AddressQuerySection) int {
	if q.SubjectAddr.String() < query.SubjectAddr.String() {
		return -1
	} else if q.SubjectAddr.String() > query.SubjectAddr.String() {
		return 1
	} else if q.Context < query.Context {
		return -1
	} else if q.Context > query.Context {
		return 1
	} else if len(q.Types) < len(query.Types) {
		return -1
	} else if len(q.Types) > len(query.Types) {
		return 1
	}
	for i, o := range q.Types {
		if o < query.Types[i] {
			return -1
		} else if o > query.Types[i] {
			return 1
		}
	}
	if q.Expiration < query.Expiration {
		return -1
	} else if q.Expiration > query.Expiration {
		return 1
	} else if len(q.Options) < len(query.Options) {
		return -1
	} else if len(q.Options) > len(query.Options) {
		return 1
	}
	for i, o := range q.Options {
		if o < query.Options[i] {
			return -1
		} else if o > query.Options[i] {
			return 1
		}
	}
	return 0
}

//String implements Stringer interface
func (q *AddressQuerySection) String() string {
	if q == nil {
		return "AddressQuery:nil"
	}
	return fmt.Sprintf("AddressQuery:[SA=%s CTX=%s TYPE=%v EXP=%d OPT=%v]",
		q.SubjectAddr, q.Context, q.Types, q.Expiration, q.Options)
}

//NotificationSection contains information about the notification
type NotificationSection struct {
	Token token.Token
	Type  NotificationType
	Data  string
}

// UnmarshalMap unpacks a CBOR unmarshaled map to this object.
func (n *NotificationSection) UnmarshalMap(m map[int]interface{}) error {
	if tok, ok := m[2]; ok {
		n.Token = Token(tok.([16]byte))
	} else {
		return fmt.Errorf("key [2] for token not found in map: %v", m)
	}
	if not, ok := m[21]; ok {
		n.Type = NotificationType(not.(int))
	} else {
		return fmt.Errorf("key [21] for NotificationType not found in map: %v", m)
	}
	if data, ok := m[22]; ok {
		n.Data = string(data.(string))
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (n *NotificationSection) MarshalCBOR(w *borat.CBORWriter) error {
	m := make(map[int]interface{})
	m[2] = n.Token
	m[21] = int(n.Type)
	m[22] = n.Data
	return w.WriteIntMap(m)
}

//Sort sorts the content of the notification lexicographically.
func (n *NotificationSection) Sort() {
	//notification is already sorted (it does not contain a list of elements).
}

//CompareTo compares two notifications and returns 0 if they are equal, 1 if n is greater than
//notification and -1 if n is smaller than notification
func (n *NotificationSection) CompareTo(notification *NotificationSection) int {
	if n.Token != notification.Token {
		for i, b := range n.Token {
			if b < notification.Token[i] {
				return -1
			} else if b > notification.Token[i] {
				return 1
			}
		}
		log.Error("Token must be different", "t1", n.Token, "t2", notification.Token)
	}
	if n.Type < notification.Type {
		return -1
	} else if n.Type > notification.Type {
		return 1
	} else if n.Data < notification.Data {
		return -1
	} else if n.Data > notification.Data {
		return 1
	}
	return 0
}

//String implements Stringer interface
func (n *NotificationSection) String() string {
	if n == nil {
		return "Notification:nil"
	}
	return fmt.Sprintf("Notification:[TOK=%s TYPE=%d DATA=%s]",
		hex.EncodeToString(n.Token[:]), n.Type, n.Data)
}

//filterSigs returns only those signatures which are in the given keySpace
func filterSigs(signatures []signature.Signature, keySpace keys.KeySpaceID) []signature.Signature {
	sigs := []signature.Signature{}
	for _, sig := range signatures {
		if sig.KeySpace == keySpace {
			sigs = append(sigs, sig)
		}
	}
	return sigs
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
	Type types.NetworkAddrType

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
