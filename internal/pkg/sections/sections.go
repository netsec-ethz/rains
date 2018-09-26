package sections

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"golang.org/x/crypto/ed25519"
)

//Section can be either an Assertion, Shard, Zone, Query, Notification, AddressAssertion, AddressZone, AddressQuery section
type Section interface {
	Sort()
	String() string
}

//SecWithSig is an interface for a section protected by a signature. In the current
//implementation it can be an Assertion, Shard, Zone, AddressAssertion, AddressZone
type SecWithSig interface {
	Section
	AllSigs() []signature.Sig
	Sigs(keyspace keys.KeySpaceID) []signature.Sig
	AddSig(sig signature.Sig)
	DeleteSig(index int)
	GetContext() string
	GetSubjectZone() string
	UpdateValidity(validSince, validUntil int64, maxValidity time.Duration)
	ValidSince() int64
	ValidUntil() int64
	Hash() string
	IsConsistent() bool
	NeededKeys(map[signature.MetaData]bool)
}

//SecWithSigForward can be either an Assertion, Shard or Zone
type SecWithSigForward interface {
	SecWithSig
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

//Hasher can be implemented by objects that are not natively hashable.
//For an object to be a map key (or a part thereof), it must be hashable.
type Hasher interface {
	//Hash must return a string uniquely identifying the object
	//It must hold for all objects that o1 == o2 iff o1.Hash() == o2.Hash()
	Hash() string
}

//Assertion contains information about the assertion.
type Assertion struct {
	Signatures  []signature.Sig
	SubjectName string
	SubjectZone string
	Context     string
	Content     []object.Object
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

// UnmarshalMap provides functionality to unmarshal a map read in by CBOR.
func (a *Assertion) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0]; ok {
		a.Signatures = make([]signature.Sig, len(sigs.([]interface{})))
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
		switch object.Type(objArr[0].(uint64)) {
		case object.OTName:
			no := object.Name{Types: make([]object.Type, 0)}
			no.Name = objArr[1].(string)
			for _, ot := range objArr[2].([]interface{}) {
				no.Types = append(no.Types, object.Type(ot.(int)))
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
			switch algorithmTypes.Signature(alg) {
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
					Algorithm: algorithmTypes.Signature(alg),
					KeySpace:  ks,
					KeyPhase:  kp,
				},
				ValidSince: vs,
				ValidUntil: vu,
				Key:        key,
			}
			a.Content = append(a.Content, object.Object{Type: object.OTDelegation, Value: pkey})
		case object.OTNameset:
			a.Content = append(a.Content, object.Object{Type: object.OTNameset, Value: object.NamesetExpr(objArr[1].(string))})
		case object.OTCertInfo:
			co := object.Certificate{
				Type:     object.ProtocolType(objArr[1].(int)),
				Usage:    object.CertificateUsage(objArr[2].(int)),
				HashAlgo: algorithmTypes.Hash(objArr[3].(int)),
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
			switch alg.(algorithmTypes.Signature) {
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
					Algorithm: alg.(algorithmTypes.Signature),
					KeySpace:  ks,
					KeyPhase:  kp,
				},
				ValidSince: vs,
				ValidUntil: vu,
				Key:        key,
			}
			a.Content = append(a.Content, object.Object{Type: object.OTInfraKey, Value: pkey})
		case object.OTExtraKey:
			alg := objArr[1].(algorithmTypes.Signature)
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
func (a *Assertion) MarshalCBOR(w *borat.CBORWriter) error {
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

func objectToArrayCBOR(obj object.Object) ([]interface{}, error) {
	var res []interface{}
	switch obj.Type {
	case object.OTName:
		no, ok := obj.Value.(object.Name)
		if !ok {
			return nil, fmt.Errorf("expected OTName to be Name but got: %T", obj.Value)
		}
		ots := make([]int, len(no.Types))
		for i, ot := range no.Types {
			ots[i] = int(ot)
		}
		res = []interface{}{object.OTName, no.Name, ots}
	case object.OTIP6Addr:
		addrStr := obj.Value.(string)
		addr := net.ParseIP(addrStr)
		res = []interface{}{object.OTIP6Addr, []byte(addr)}
	case object.OTIP4Addr:
		addrStr := obj.Value.(string)
		addr := net.ParseIP(addrStr)
		res = []interface{}{object.OTIP4Addr, []byte(addr)}
	case object.OTRedirection:
		res = []interface{}{object.OTRedirection, obj.Value}
	case object.OTDelegation:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", obj.Value)
		}
		// TODO: ValidSince and ValidUntil should be tagged.
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{object.OTDelegation, int(pkey.Algorithm), int(pkey.KeySpace), pkey.KeyPhase, pkey.ValidSince, pkey.ValidUntil, b}
	case object.OTNameset:
		nse, ok := obj.Value.(object.NamesetExpr)
		if !ok {
			return nil, fmt.Errorf("expected OTNameset value to be NamesetExpr but got: %T", obj.Value)
		}
		res = []interface{}{object.OTNameset, string(nse)}
	case object.OTCertInfo:
		co, ok := obj.Value.(object.Certificate)
		if !ok {
			return nil, fmt.Errorf("expected OTCertInfo object to be Certificate, but got: %T", obj.Value)
		}
		res = []interface{}{object.OTCertInfo, int(co.Type), int(co.Usage), int(co.HashAlgo), co.Data}
	case object.OTServiceInfo:
		si, ok := obj.Value.(object.ServiceInfo)
		if !ok {
			return nil, fmt.Errorf("expected OTServiceInfo object to be ServiceInfo, but got: %T", obj.Value)
		}
		res = []interface{}{object.OTServiceInfo, si.Name, si.Port, si.Priority}
	case object.OTRegistrar:
		rstr, ok := obj.Value.(string)
		if !ok {
			return nil, fmt.Errorf("expected OTRegistrar object to be string but got: %T", obj.Value)
		}
		res = []interface{}{object.OTRegistrar, rstr}
	case object.OTRegistrant:
		rstr, ok := obj.Value.(string)
		if !ok {
			return nil, fmt.Errorf("expected OTRegistrant object to be string but got: %T", obj.Value)
		}
		res = []interface{}{object.OTRegistrant, rstr}
	case object.OTInfraKey:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", obj.Value)
		}
		// TODO: ValidSince and ValidUntl should be tagged.
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{object.OTInfraKey, int(pkey.Algorithm), int(pkey.KeySpace), pkey.KeyPhase, pkey.ValidSince, pkey.ValidUntil, b}
	case object.OTExtraKey:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", obj.Value)
		}
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{object.OTExtraKey, int(pkey.Algorithm), int(pkey.KeySpace), b}
	case object.OTNextKey:
	default:
		return nil, fmt.Errorf("unknown object type: %v", obj.Type)
	}
	return res, nil
}

func pubkeyToCBORBytes(p keys.PublicKey) []byte {
	switch p.Algorithm {
	case algorithmTypes.Ed25519:
		return []byte(p.Key.(ed25519.PublicKey))
	case algorithmTypes.Ed448:
		panic("Unsupported algorithm.")
	case algorithmTypes.Ecdsa256:
		panic("Unsupported algorithm.")
	case algorithmTypes.Ecdsa384:
		panic("Unsupported algorithm.")
	default:
		panic("Unsupported algorithm.")
	}
}

//AllSigs returns all assertion's signatures
func (a *Assertion) AllSigs() []signature.Sig {
	return a.Signatures
}

//Sigs returns a's signatures in keyspace
func (a *Assertion) Sigs(keySpace keys.KeySpaceID) []signature.Sig {
	return filterSigs(a.Signatures, keySpace)
}

//AddSig adds the given signature
func (a *Assertion) AddSig(sig signature.Sig) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *Assertion) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//GetContext returns the context of the assertion
func (a *Assertion) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the zone of the assertion
func (a *Assertion) GetSubjectZone() string {
	return a.SubjectZone
}

//Copy creates a copy of the assertion with the given context and subjectZone values
func (a *Assertion) Copy(context, subjectZone string) *Assertion {
	stub := &Assertion{}
	*stub = *a
	stub.Context = context
	stub.SubjectZone = subjectZone
	return stub
}

//Begin returns the begining of the interval of this assertion.
func (a *Assertion) Begin() string {
	return a.SubjectName
}

//End returns the end of the interval of this assertion.
func (a *Assertion) End() string {
	return a.SubjectName
}

//UpdateValidity updates the validity of this assertion if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (a *Assertion) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
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
func (a *Assertion) ValidSince() int64 {
	return a.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (a *Assertion) ValidUntil() int64 {
	return a.validUntil
}

//Hash returns a string containing all information uniquely identifying an assertion.
func (a *Assertion) Hash() string {
	if a == nil {
		return "A_nil"
	}
	return fmt.Sprintf("A_%s_%s_%s_%v_%v",
		a.SubjectName, a.SubjectZone, a.Context, a.Content, a.Signatures)
}

//EqualContextZoneName return true if the given assertion has the same context, subjectZone,
//subjectName.
func (a *Assertion) EqualContextZoneName(assertion *Assertion) bool {
	if assertion == nil {
		return false
	}
	return a.Context == assertion.Context &&
		a.SubjectZone == assertion.SubjectZone &&
		a.SubjectName == assertion.SubjectName
}

//Sort sorts the content of the assertion lexicographically.
func (a *Assertion) Sort() {
	for _, o := range a.Content {
		o.Sort()
	}
	sort.Slice(a.Content, func(i, j int) bool { return a.Content[i].CompareTo(a.Content[j]) < 0 })
}

//CompareTo compares two assertions and returns 0 if they are equal, 1 if a is greater than
//assertion and -1 if a is smaller than assertion
func (a *Assertion) CompareTo(assertion *Assertion) int {
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
func (a *Assertion) String() string {
	if a == nil {
		return "Assertion:nil"
	}
	return fmt.Sprintf("Assertion:[SN=%s SZ=%s CTX=%s CONTENT=%v SIG=%v]",
		a.SubjectName, a.SubjectZone, a.Context, a.Content, a.Signatures)
}

//IsConsistent returns true. Assertion is always consistent.
func (a *Assertion) IsConsistent() bool {
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all a's signatures.
func (a *Assertion) NeededKeys(keysNeeded map[signature.MetaData]bool) {
	extractNeededKeys(a, keysNeeded)
}

//extractNeededKeys adds all key metadata to sigData which are necessary to verify all section's
//signatures.
func extractNeededKeys(section SecWithSig, sigData map[signature.MetaData]bool) {
	for _, sig := range section.Sigs(keys.RainsKeySpace) {
		sigData[sig.MetaData()] = true
	}
}

//BloomFilterEncoding returns a string encoding of the assertion to add to or query a bloom filter
func (a *Assertion) BloomFilterEncoding() string {
	return fmt.Sprintf("%s.%s %s %d", a.SubjectName, a.SubjectZone, a.Context, a.Content[0].Type)
}

//Shard contains information about the shard
type Shard struct {
	Signatures  []signature.Sig
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
	Content     []*Assertion
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

// UnmarshalMap converts a CBOR decoded map to this Shard.
func (s *Shard) UnmarshalMap(m map[int]interface{}) error {
	s.Signatures = make([]signature.Sig, 0)
	if sigs, ok := m[0]; ok {
		s.Signatures = make([]signature.Sig, len(sigs.([]interface{})))
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
		s.Content = make([]*Assertion, 0)
		for _, obj := range cont.([]interface{}) {
			as := &Assertion{}
			as.UnmarshalMap(obj.(map[int]interface{}))
			s.Content = append(s.Content, as)
		}
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (s *Shard) MarshalCBOR(w *borat.CBORWriter) error {
	fmt.Printf("Called MarshalCBOR on Shard")
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
func (s *Shard) AllSigs() []signature.Sig {
	return s.Signatures
}

//Sigs returns s's signatures in keyspace
func (s *Shard) Sigs(keySpace keys.KeySpaceID) []signature.Sig {
	return filterSigs(s.Signatures, keySpace)
}

//AddSig adds the given signature
func (s *Shard) AddSig(sig signature.Sig) {
	s.Signatures = append(s.Signatures, sig)
}

//DeleteSig deletes ith signature
func (s *Shard) DeleteSig(i int) {
	s.Signatures = append(s.Signatures[:i], s.Signatures[i+1:]...)
}

//GetContext returns the context of the shard
func (s *Shard) GetContext() string {
	return s.Context
}

//GetSubjectZone returns the zone of the shard
func (s *Shard) GetSubjectZone() string {
	return s.SubjectZone
}

//Copy creates a copy of the shard with the given context and subjectZone values. The contained
//assertions are not modified
func (s *Shard) Copy(context, subjectZone string) *Shard {
	stub := &Shard{}
	*stub = *s
	stub.Context = context
	stub.SubjectZone = subjectZone
	return stub
}

//Begin returns the begining of the interval of this shard.
func (s *Shard) Begin() string {
	return s.RangeFrom
}

//End returns the end of the interval of this shard.
func (s *Shard) End() string {
	return s.RangeTo
}

//UpdateValidity updates the validity of this shard if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (s *Shard) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
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
func (s *Shard) ValidSince() int64 {
	return s.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (s *Shard) ValidUntil() int64 {
	return s.validUntil
}

//Hash returns a string containing all information uniquely identifying a shard.
func (s *Shard) Hash() string {
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
func (s *Shard) Sort() {
	for _, a := range s.Content {
		a.Sort()
	}
	sort.Slice(s.Content, func(i, j int) bool { return s.Content[i].CompareTo(s.Content[j]) < 0 })
}

//CompareTo compares two shards and returns 0 if they are equal, 1 if s is greater than shard and -1
//if s is smaller than shard
func (s *Shard) CompareTo(shard *Shard) int {
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
func (s *Shard) String() string {
	if s == nil {
		return "Shard:nil"
	}
	return fmt.Sprintf("Shard:[SZ=%s CTX=%s RF=%s RT=%s CONTENT=%v SIG=%v]",
		s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo, s.Content, s.Signatures)
}

//AssertionsByNameAndTypes returns all contained assertions with subjectName and at least one object
//that has a type contained in connection. It is assumed that the contained assertions are sorted by
//subjectName in ascending order. The returned assertions are pairwise distinct.
func (s *Shard) AssertionsByNameAndTypes(subjectName string, types []object.Type) []*Assertion {
	assertionMap := make(map[string]*Assertion)
	i := sort.Search(len(s.Content), func(i int) bool { return s.Content[i].SubjectName >= subjectName })
	for ; i < len(s.Content) && s.Content[i].SubjectName == subjectName; i++ {
		for _, oType := range types {
			if _, ok := object.ContainsType(s.Content[i].Content, oType); ok {
				assertionMap[s.Content[i].Hash()] = s.Content[i]
				break
			}
		}
	}
	var assertions []*Assertion
	for _, a := range assertionMap {
		assertions = append(assertions, a)
	}
	return assertions
}

//InRange returns true if subjectName is inside the shard range
func (s *Shard) InRange(subjectName string) bool {
	return (s.RangeFrom == "" && s.RangeTo == "") || (s.RangeFrom == "" && s.RangeTo > subjectName) ||
		(s.RangeTo == "" && s.RangeFrom < subjectName) ||
		(s.RangeFrom < subjectName && s.RangeTo > subjectName)
}

//AddZoneAndContextToAssertions adds the shard's subjectZone and context value to all contained
//assertions
func (s *Shard) AddZoneAndContextToAssertions() {
	for _, a := range s.Content {
		a.SubjectZone = s.SubjectZone
		a.Context = s.Context
	}
}

//IsConsistent returns true if all contained assertions have no subjectZone and context and are
//within the shards range.
func (s *Shard) IsConsistent() bool {
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
func sectionHasContextOrSubjectZone(section SecWithSig) bool {
	return section.GetSubjectZone() != "" || section.GetContext() != ""
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all s's signatures.
func (s *Shard) NeededKeys(keysNeeded map[signature.MetaData]bool) {
	extractNeededKeys(s, keysNeeded)
	for _, a := range s.Content {
		a.NeededKeys(keysNeeded)
	}
}

//Pshard contains information about a pshard
type Pshard struct {
	Signatures    []signature.Sig
	SubjectZone   string
	Context       string
	RangeFrom     string
	RangeTo       string
	Datastructure DataStructure
	validSince    int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil    int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//AllSigs returns the pshard's signatures
func (s *Pshard) AllSigs() []signature.Sig {
	return s.Signatures
}

//Sigs returns s's signatures in keyspace
func (s *Pshard) Sigs(keySpace keys.KeySpaceID) []signature.Sig {
	return filterSigs(s.Signatures, keySpace)
}

//AddSig adds the given signature
func (s *Pshard) AddSig(sig signature.Sig) {
	s.Signatures = append(s.Signatures, sig)
}

//DeleteSig deletes ith signature
func (s *Pshard) DeleteSig(i int) {
	s.Signatures = append(s.Signatures[:i], s.Signatures[i+1:]...)
}

//GetContext returns the context of the pshard
func (s *Pshard) GetContext() string {
	return s.Context
}

//GetSubjectZone returns the zone of the pshard
func (s *Pshard) GetSubjectZone() string {
	return s.SubjectZone
}

//Begin returns the begining of the interval of this pshard.
func (s *Pshard) Begin() string {
	return s.RangeFrom
}

//End returns the end of the interval of this pshard.
func (s *Pshard) End() string {
	return s.RangeTo
}

//UpdateValidity updates the validity of this pshard if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (s *Pshard) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
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
func (s *Pshard) ValidSince() int64 {
	return s.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (s *Pshard) ValidUntil() int64 {
	return s.validUntil
}

//Hash returns a string containing all information uniquely identifying a pshard.
func (s *Pshard) Hash() string {
	if s == nil {
		return "S_nil"
	}
	return fmt.Sprintf("S_%s_%s_%s_%s_%v_%v", s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo,
		s.Datastructure, s.Signatures)
}

//Sort sorts the content of the pshard lexicographically.
func (s *Pshard) Sort() {
	//nothing to sort
}

//CompareTo compares two shards and returns 0 if they are equal, 1 if s is greater than shard and -1
//if s is smaller than shard
func (s *Pshard) CompareTo(shard *Pshard) int {
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
func (s *Pshard) String() string {
	if s == nil {
		return "Shard:nil"
	}
	return fmt.Sprintf("Shard:[SZ=%s CTX=%s RF=%s RT=%s DS=%v SIG=%v]",
		s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo, s.Datastructure, s.Signatures)
}

//InRange returns true if subjectName is inside the shard range
func (s *Pshard) InRange(subjectName string) bool {
	return (s.RangeFrom == "" && s.RangeTo == "") || (s.RangeFrom == "" && s.RangeTo > subjectName) ||
		(s.RangeTo == "" && s.RangeFrom < subjectName) ||
		(s.RangeFrom < subjectName && s.RangeTo > subjectName)
}

//IsConsistent returns true if all contained assertions have no subjectZone and context and are
//within the shards range.
func (s *Pshard) IsConsistent() bool {
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all s's signatures.
func (s *Pshard) NeededKeys(keysNeeded map[signature.MetaData]bool) {
	extractNeededKeys(s, keysNeeded)
}

//Zone contains information about the zone
type Zone struct {
	Signatures  []signature.Sig
	SubjectZone string
	Context     string
	Content     []SecWithSigForward
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (z *Zone) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0]; ok {
		z.Signatures = make([]signature.Sig, len(sigs.([]interface{})))
		for i, sig := range sigs.([]interface{}) {
			if err := z.Signatures[i].UnmarshalArray(sig.([]interface{})); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("missing signatures from Zone")
	}
	if sz, ok := m[4]; ok {
		z.SubjectZone = sz.(string)
	} else {
		return fmt.Errorf("missing SubjectZone from Zone")
	}
	if ctx, ok := m[6]; ok {
		z.Context = ctx.(string)
	} else {
		return fmt.Errorf("missing Context from Zone")
	}
	// Content is an array of ShardSections and / or AssertionSections.
	if content, ok := m[23]; ok {
		z.Content = make([]SecWithSigForward, 0)
		for _, item := range content.([]interface{}) {
			m := item.(map[int]interface{})
			if _, ok := m[11]; ok {
				// Shard.
				ss := &Shard{}
				if err := ss.UnmarshalMap(m); err != nil {
					return fmt.Errorf("failed to unmarshal Shard map in Zone: %v", err)
				}
				z.Content = append(z.Content, ss)
			} else {
				// Assertion.
				as := &Assertion{}
				if err := as.UnmarshalMap(m); err != nil {
					return fmt.Errorf("failed to unmarshal Assertion map in Zone: %v", err)
				}
				z.Content = append(z.Content, as)
			}
		}
	} else {
		return fmt.Errorf("missing content for Zone")
	}
	return nil
}

func (z *Zone) MarshalCBOR(w *borat.CBORWriter) error {
	m := make(map[int]interface{})
	m[23] = z.Content
	m[0] = z.Signatures
	m[4] = z.SubjectZone
	m[6] = z.Context
	return w.WriteIntMap(m)
}

//AllSigs returns the zone's signatures
func (z *Zone) AllSigs() []signature.Sig {
	return z.Signatures
}

//Sigs returns z's signatures in keyspace
func (z *Zone) Sigs(keySpace keys.KeySpaceID) []signature.Sig {
	return filterSigs(z.Signatures, keySpace)
}

//AddSig adds the given signature
func (z *Zone) AddSig(sig signature.Sig) {
	z.Signatures = append(z.Signatures, sig)
}

//DeleteSig deletes ith signature
func (z *Zone) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//GetContext returns the context of the zone
func (z *Zone) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the zone of the zone
func (z *Zone) GetSubjectZone() string {
	return z.SubjectZone
}

//Begin returns the begining of the interval of this zone.
func (z *Zone) Begin() string {
	return ""
}

//End returns the end of the interval of this zone.
func (z *Zone) End() string {
	return ""
}

//UpdateValidity updates the validity of this zone if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (z *Zone) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
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
func (z *Zone) ValidSince() int64 {
	return z.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (z *Zone) ValidUntil() int64 {
	return z.validUntil
}

//Hash returns a string containing all information uniquely identifying a shard.
func (z *Zone) Hash() string {
	if z == nil {
		return "Z_nil"
	}
	contentHashes := []string{}
	for _, v := range z.Content {
		switch v := v.(type) {
		case *Assertion, *Shard:
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
func (z *Zone) Sort() {
	for _, s := range z.Content {
		s.Sort()
	}
	sort.Slice(z.Content, func(i, j int) bool {
		switch section := z.Content[i].(type) {
		case *Assertion:
			if a, ok := z.Content[j].(*Assertion); ok {
				return section.CompareTo(a) < 0
			}
			return true
		case *Pshard:
			if s, ok := z.Content[j].(*Pshard); ok {
				return section.CompareTo(s) < 0
			}
			if _, ok := z.Content[j].(*Assertion); ok {
				return false
			}
			return true //it is a shard
		case *Shard:
			if s, ok := z.Content[j].(*Shard); ok {
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
func (z *Zone) CompareTo(zone *Zone) int {
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
		case *Assertion:
			if a, ok := zone.Content[i].(*Assertion); ok {
				if section.CompareTo(a) != 0 {
					return section.CompareTo(a)
				}
			} else {
				return -1
			}
		case *Shard:
			if s, ok := zone.Content[i].(*Shard); ok {
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
func (z *Zone) String() string {
	if z == nil {
		return "Zone:nil"
	}
	return fmt.Sprintf("Zone:[SZ=%s CTX=%s CONTENT=%v SIG=%v]",
		z.SubjectZone, z.Context, z.Content, z.Signatures)
}

//SectionsByNameAndTypes returns all contained assertions with subjectName and at least one object
//that has a type contained in connection together with all contained shards having subjectName in their
//range. It is assumed that the contained sections are sorted as for signing. The returned
//assertions and shards are pairwise distinct.
func (z *Zone) SectionsByNameAndTypes(subjectName string, types []object.Type) (
	[]*Assertion, []*Shard) {
	assertionMap := make(map[string]*Assertion)
	shardMap := make(map[string]*Shard)

	//extract assertions matching subjectName
	i := sort.Search(len(z.Content), func(i int) bool {
		if a, ok := z.Content[i].(*Assertion); ok {
			return a.SubjectName >= subjectName
		}
		return true
	})
	for ; i < len(z.Content); i++ {
		if a, ok := z.Content[i].(*Assertion); ok && a.SubjectName == subjectName {
			for _, oType := range types {
				if _, ok := object.ContainsType(a.Content, oType); ok {
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
		_, ok := z.Content[i].(*Shard)
		return ok
	})
	for ; i < len(z.Content); i++ {
		if s, ok := z.Content[i].(*Shard); ok && s.RangeFrom < subjectName {
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

	var assertions []*Assertion
	for _, a := range assertionMap {
		assertions = append(assertions, a)
	}
	var shards []*Shard
	for _, s := range shardMap {
		shards = append(shards, s)
	}
	return assertions, shards
}

//AddZoneAndContextToSections adds the zone's subjectZone and context value to all contained
//assertions and shards
func (z *Zone) AddZoneAndContextToSections() {
	for _, sec := range z.Content {
		switch sec := sec.(type) {
		case *Assertion:
			sec.SubjectZone = z.SubjectZone
			sec.Context = z.Context
		case *Shard:
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
func (z *Zone) IsConsistent() bool {
	for _, section := range z.Content {
		if sectionHasContextOrSubjectZone(section) {
			log.Warn("Contained section has a subjectZone or context", "section", section)
			return false
		}
		if shard := section.(*Shard); !shard.IsConsistent() {
			return false //already logged
		}
	}
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all z's signatures.
func (z *Zone) NeededKeys(keysNeeded map[signature.MetaData]bool) {
	extractNeededKeys(z, keysNeeded)
	for _, section := range z.Content {
		section.NeededKeys(keysNeeded)
	}
}

//QueryForward contains information about the query
type QueryForward struct {
	Context    string
	Name       string
	Types      []object.Type
	Expiration int64 //unix seconds
	Options    []QueryOption
}

// UnmarshalMap unpacks a CBOR marshaled map to this struct.
func (q *QueryForward) UnmarshalMap(m map[int]interface{}) error {
	q.Name = m[8].(string)
	q.Context = m[6].(string)
	q.Types = make([]object.Type, 0)
	if types, ok := m[10]; ok {
		for _, qt := range types.([]interface{}) {
			q.Types = append(q.Types, object.Type(qt.(uint64)))
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
func (q *QueryForward) MarshalCBOR(w *borat.CBORWriter) error {
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
func (q *QueryForward) GetContext() string {
	return q.Context
}

//GetExpiration returns q's expiration
func (q *QueryForward) GetExpiration() int64 {
	return q.Expiration
}

//ContainsOption returns true if the query contains the given query option.
func (q *QueryForward) ContainsOption(option QueryOption) bool {
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
func (q *QueryForward) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two queries and returns 0 if they are equal, 1 if q is greater than query and
//-1 if q is smaller than query
func (q *QueryForward) CompareTo(query *QueryForward) int {
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
func (q *QueryForward) String() string {
	if q == nil {
		return "Query:nil"
	}
	return fmt.Sprintf("Query:[CTX=%s NA=%s TYPE=%v EXP=%d OPT=%v]",
		q.Context, q.Name, q.Types, q.Expiration, q.Options)
}

type AssertionUpdate struct {
	Name       string
	HashType   algorithmTypes.Hash
	HashValue  []byte
	Expiration int64 //unix seconds
	Options    []QueryOption
}

//String implements Stringer interface
func (q *AssertionUpdate) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[NA=%s HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Name, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration, q.Options)
}

type NegUpdate struct {
	Context     string
	Name        string
	ObjectTypes []object.Type
	HashType    algorithmTypes.Hash
	HashValue   []byte
	Expiration  int64 //unix seconds
	Options     []QueryOption
}

//String implements Stringer interface
func (q *NegUpdate) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[CTX=%s NA=%s OTYPE=%v HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Context, q.Name, q.ObjectTypes, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration,
		q.Options)
}

//AddrAssertion contains information about the address assertion
type AddrAssertion struct {
	Signatures  []signature.Sig
	SubjectAddr *net.IPNet
	Context     string
	Content     []object.Object
	validSince  int64
	validUntil  int64
}

// MarshalCBOR implements the CBORMarshaler interface.
func (a *AddrAssertion) MarshalCBOR(w *borat.CBORWriter) error {
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
func (a *AddrAssertion) AllSigs() []signature.Sig {
	return a.Signatures
}

//Sigs returns a's signatures in keyspace
func (a *AddrAssertion) Sigs(keySpace keys.KeySpaceID) []signature.Sig {
	return filterSigs(a.Signatures, keySpace)
}

//AddSig adds the given signature
func (a *AddrAssertion) AddSig(sig signature.Sig) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *AddrAssertion) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//GetContext returns the context of the assertion
func (a *AddrAssertion) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the SubjectAddr
func (a *AddrAssertion) GetSubjectZone() string {
	return a.SubjectAddr.String()
}

//UpdateValidity updates the validity of this assertion if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (a *AddrAssertion) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
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
func (a *AddrAssertion) ValidSince() int64 {
	return a.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (a *AddrAssertion) ValidUntil() int64 {
	return a.validUntil
}

//Hash returns a string containing all information uniquely identifying an assertion.
func (a *AddrAssertion) Hash() string {
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
func (a *AddrAssertion) Sort() {
	for _, o := range a.Content {
		o.Sort()
	}
	sort.Slice(a.Content, func(i, j int) bool { return a.Content[i].CompareTo(a.Content[j]) < 0 })
}

//CompareTo compares two addressAssertions and returns 0 if they are equal, 1 if a is greater than
//assertion and -1 if a is smaller than assertion
func (a *AddrAssertion) CompareTo(assertion *AddrAssertion) int {
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
func (a *AddrAssertion) String() string {
	if a == nil {
		return "AddressAssertion:nil"
	}
	return fmt.Sprintf("AddressAssertion:[SA=%s CTX=%s CONTENT=%v SIG=%v]",
		a.SubjectAddr, a.Context, a.Content, a.Signatures)
}

//IsConsistent returns false if the addressAssertion contains not allowed object connection
func (a *AddrAssertion) IsConsistent() bool {
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
func invalidObjectType(subjectAddr *net.IPNet, objectType object.Type) bool {
	prefixLength, addressLength := subjectAddr.Mask.Size()
	if addressLength == 32 {
		if prefixLength == 32 {
			return objectType != object.OTName
		}
		return objectType != object.OTDelegation && objectType != object.OTRedirection && objectType != object.OTRegistrant
	}
	if addressLength == 128 {
		if prefixLength == 128 {
			return objectType != object.OTName
		}
		return objectType != object.OTDelegation && objectType != object.OTRedirection && objectType != object.OTRegistrant
	}
	log.Warn("Invalid addressLength", "addressLength", addressLength)
	return true
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all a's signatures.
func (a *AddrAssertion) NeededKeys(keysNeeded map[signature.MetaData]bool) {
	extractNeededKeys(a, keysNeeded)
}

//AddrQuery contains information about the address query
type AddrQuery struct {
	SubjectAddr *net.IPNet
	Context     string
	Types       []object.Type
	Expiration  int64 //Unix seconds
	Options     []QueryOption
}

//GetContext returns q's context
func (q *AddrQuery) GetContext() string {
	return q.Context
}

//GetExpiration returns q's expiration
func (q *AddrQuery) GetExpiration() int64 {
	return q.Expiration
}

//ContainsOption returns true if the address query contains the given query option.
func (q *AddrQuery) ContainsOption(option QueryOption) bool {
	return containsOption(option, q.Options)
}

//Sort sorts the content of the addressQuery lexicographically.
func (q *AddrQuery) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two addressQueries and returns 0 if they are equal, 1 if q is greater than
//query and -1 if q is smaller than query
func (q *AddrQuery) CompareTo(query *AddrQuery) int {
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
func (q *AddrQuery) String() string {
	if q == nil {
		return "AddressQuery:nil"
	}
	return fmt.Sprintf("AddressQuery:[SA=%s CTX=%s TYPE=%v EXP=%d OPT=%v]",
		q.SubjectAddr, q.Context, q.Types, q.Expiration, q.Options)
}

//Notification contains information about the notification
type Notification struct {
	Token token.Token
	Type  NotificationType
	Data  string
}

// UnmarshalMap unpacks a CBOR unmarshaled map to this object.
func (n *Notification) UnmarshalMap(m map[int]interface{}) error {
	if tok, ok := m[2]; ok {
		n.Token = tok.(token.Token)
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
func (n *Notification) MarshalCBOR(w *borat.CBORWriter) error {
	m := make(map[int]interface{})
	m[2] = n.Token
	m[21] = int(n.Type)
	m[22] = n.Data
	return w.WriteIntMap(m)
}

//Sort sorts the content of the notification lexicographically.
func (n *Notification) Sort() {
	//notification is already sorted (it does not contain a list of elements).
}

//CompareTo compares two notifications and returns 0 if they are equal, 1 if n is greater than
//notification and -1 if n is smaller than notification
func (n *Notification) CompareTo(notification *Notification) int {
	if comp := token.Compare(n.Token, notification.Token); comp != 0 {
		return comp
	} else if n.Type < notification.Type {
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
func (n *Notification) String() string {
	if n == nil {
		return "Notification:nil"
	}
	return fmt.Sprintf("Notification:[TOK=%s TYPE=%d DATA=%s]",
		hex.EncodeToString(n.Token[:]), n.Type, n.Data)
}

//filterSigs returns only those signatures which are in the given keySpace
func filterSigs(signatures []signature.Sig, keySpace keys.KeySpaceID) []signature.Sig {
	sigs := []signature.Sig{}
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
