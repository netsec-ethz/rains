package section

import (
	"fmt"
	"math"
	"net"
	"sort"
	"time"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

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
func (a *AddrAssertion) MarshalCBOR(w *cbor.CBORWriter) error {
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
	m[7] = a.Content
	return w.WriteIntMap(m)
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (a *AddrAssertion) UnmarshalMap(m map[int]interface{}) error {
	//TODO CFE to implement
	return nil
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

//DeleteAllSigs deletes all signature
func (a *AddrAssertion) DeleteAllSigs() {
	a.Signatures = []signature.Sig{}
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
