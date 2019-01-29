package section

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	cbor "github.com/britram/borat"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
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
	sign        bool  //set to true before signing and false afterwards
}

// UnmarshalMap provides functionality to unmarshal a map read in by CBOR.
func (a *Assertion) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0].([]interface{}); ok {
		a.Signatures = make([]signature.Sig, len(sigs))
		for i, sig := range sigs {
			sigVal, ok := sig.([]interface{})
			if !ok {
				return errors.New("cbor assertion signatures entry is not an array")
			}
			if err := a.Signatures[i].UnmarshalArray(sigVal); err != nil {
				return err
			}
		}
	}
	if sn, ok := m[3].(string); ok {
		a.SubjectName = sn
	} else {
		return errors.New("cbor assertion map does not contain a subject name")
	}
	if sz, ok := m[4].(string); ok {
		a.SubjectZone = sz
	} //subject zone is omitted in a contained assertion

	if ctx, ok := m[6].(string); ok {
		a.Context = ctx
	} //context is omitted in a contained assertion

	if objs, ok := m[7]; ok {
		a.Content = make([]object.Object, len(objs.([]interface{})))
		for i, obj := range objs.([]interface{}) {
			if err := a.Content[i].UnmarshalArray(obj.([]interface{})); err != nil {
				return err
			}
		}
	} else {
		return errors.New("cbor assertion map does not contain an object array")
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (a *Assertion) MarshalCBOR(w *cbor.CBORWriter) error {
	m := make(map[int]interface{})
	if len(a.Signatures) > 0 && !a.sign {
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
	m[7] = a.Content
	return w.WriteIntMap(m)
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

//DeleteAllSigs deletes all signature
func (a *Assertion) DeleteAllSigs() {
	a.Signatures = []signature.Sig{}
}

//GetContext returns the context of the assertion
func (a *Assertion) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the zone of the assertion
func (a *Assertion) GetSubjectZone() string {
	return a.SubjectZone
}

//FQDN returns the fully qualified domain name of this assertion
func (a *Assertion) FQDN() string {
	if a.SubjectName == "@" {
		return a.SubjectZone
	}
	if a.SubjectZone == "." {
		return a.SubjectName + a.SubjectZone
	}
	return fmt.Sprintf("%s.%s", a.SubjectName, a.SubjectZone)
}

func (a *Assertion) SetContext(ctx string) {
	a.Context = ctx
}
func (a *Assertion) SetSubjectZone(zone string) {
	a.SubjectZone = zone
}
func (a *Assertion) RemoveContextAndSubjectZone() {
	a.SubjectZone = ""
	a.Context = ""
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
	a.validSince, a.validUntil = UpdateValidity(validSince, validUntil, a.validSince, a.validUntil,
		maxValidity)
}

//ValidSince returns the earliest validSince date of all contained signatures
func (a *Assertion) ValidSince() int64 {
	return a.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (a *Assertion) ValidUntil() int64 {
	return a.validUntil
}

//SetValidSince sets the validSince time
func (a *Assertion) SetValidSince(validSince int64) {
	a.validSince = validSince
}

//SetValidUntil sets the validUntil time
func (a *Assertion) SetValidUntil(validUntil int64) {
	a.validUntil = validUntil
}

//Hash returns a string containing all information uniquely identifying an assertion.
func (a *Assertion) Hash() string {
	if a == nil {
		return "A_nil"
	}
	encoding := new(bytes.Buffer)
	w := cbor.NewCBORWriter(encoding)
	w.WriteArray([]interface{}{1, a})
	return encoding.String()
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
	return fmt.Sprintf("Assertion:[SN=%s SZ=%s CTX=%s CONTENT=%v SIG=%v isSign=%t]",
		a.SubjectName, a.SubjectZone, a.Context, a.Content, a.Signatures, a.sign)
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
func extractNeededKeys(section WithSig, sigData map[signature.MetaData]bool) {
	for _, sig := range section.Sigs(keys.RainsKeySpace) {
		sigData[sig.MetaData()] = true
	}
}

func (a *Assertion) AddSigInMarshaller() {
	a.sign = false
}
func (a *Assertion) DontAddSigInMarshaller() {
	a.sign = true
}
