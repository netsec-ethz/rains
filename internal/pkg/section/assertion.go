package section

import (
	"fmt"
	"math"
	"net"
	"sort"
	"time"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"golang.org/x/crypto/ed25519"
)

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
