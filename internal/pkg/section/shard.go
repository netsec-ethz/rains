package section

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

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
