package section

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
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
	sign        bool  //set to true before signing and false afterwards
}

// UnmarshalMap converts a CBOR decoded map to this Shard.
func (s *Shard) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0].([]interface{}); ok {
		s.Signatures = make([]signature.Sig, len(sigs))
		for i, sig := range sigs {
			sigVal, ok := sig.([]interface{})
			if !ok {
				return errors.New("cbor zone signatures entry is not an array")
			}
			if err := s.Signatures[i].UnmarshalArray(sigVal); err != nil {
				return err
			}
		}
	} else {
		return errors.New("cbor zone map does not contain a signature")
	}
	// SubjectZone
	if zone, ok := m[4].(string); ok {
		s.SubjectZone = zone
	} else {
		return errors.New("cbor shard map does not contain a subject zone")
	}
	// Context
	if ctx, ok := m[6].(string); ok {
		s.Context = ctx
	} else {
		return errors.New("cbor shard map does not contain a context")
	}
	// RangeFrom/RangeTo
	if srange, ok := m[11].([]interface{}); ok {
		begin, ok := srange[0].(string)
		if !ok {
			return errors.New("cbor shard encoding of rangeFrom should be a string")
		}
		s.RangeFrom = begin
		end, ok := srange[1].(string)
		if !ok {
			return errors.New("cbor shard encoding of rangeEnd should be a string")
		}
		s.RangeTo = end
	} else {
		return errors.New("cbor shard map does not contain a range")
	}
	// Content
	if cont, ok := m[23].([]interface{}); ok {
		s.Content = make([]*Assertion, 0)
		for _, obj := range cont {
			as := &Assertion{}
			a, ok := obj.(map[int]interface{})
			if !ok {
				return errors.New("cbor shard content entry is not a map")
			}
			if err := as.UnmarshalMap(a); err != nil {
				return err
			}
			s.Content = append(s.Content, as)
		}
	} else {
		return errors.New("cbor shard map does not contain a content")
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (s *Shard) MarshalCBOR(w *cbor.CBORWriter) error {
	m := make(map[int]interface{})
	if len(s.Signatures) > 0 && !s.sign {
		m[0] = s.Signatures
	}
	if s.SubjectZone != "" {
		m[4] = s.SubjectZone
	}
	if s.Context != "" {
		m[6] = s.Context
	}
	m[11] = []string{s.RangeFrom, s.RangeTo}
	m[23] = s.Content
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

//DeleteAllSigs deletes all signature
func (s *Shard) DeleteAllSigs() {
	s.Signatures = []signature.Sig{}
}

//GetContext returns the context of the shard
func (s *Shard) GetContext() string {
	return s.Context
}

//GetSubjectZone returns the zone of the shard
func (s *Shard) GetSubjectZone() string {
	return s.SubjectZone
}

func (s *Shard) AddCtxAndZoneToContent() {
	for _, a := range s.Content {
		a.Context = s.Context
		a.SubjectZone = s.SubjectZone
	}
}

func (s *Shard) RemoveCtxAndZoneFromContent() {
	for _, a := range s.Content {
		a.Context = ""
		a.SubjectZone = ""
	}
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
	s.validSince, s.validUntil = UpdateValidity(validSince, validUntil, s.validSince, s.validUntil,
		maxValidity)
}

//ValidSince returns the earliest validSince date of all contained signatures
func (s *Shard) ValidSince() int64 {
	return s.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (s *Shard) ValidUntil() int64 {
	return s.validUntil
}

//SetValidSince sets the validSince time
func (s *Shard) SetValidSince(validSince int64) {
	s.validSince = validSince
}

//SetValidUntil sets the validUntil time
func (s *Shard) SetValidUntil(validUntil int64) {
	s.validUntil = validUntil
}

//Hash returns a string containing all information uniquely identifying a shard.
func (s *Shard) Hash() string {
	if s == nil {
		return "S_nil"
	}
	encoding := new(bytes.Buffer)
	w := cbor.NewCBORWriter(encoding)
	w.WriteArray([]interface{}{2, s})
	return encoding.String()
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

//InRange returns true if subjectName is inside the shard range
func (s *Shard) InRange(subjectName string) bool {
	return (s.RangeFrom == "<" && s.RangeTo == ">") || (s.RangeFrom == "<" && s.RangeTo > subjectName) ||
		(s.RangeTo == ">" && s.RangeFrom < subjectName) ||
		(s.RangeFrom < subjectName && s.RangeTo > subjectName) ||
		(s.RangeFrom == "" && s.RangeTo == "") || (s.RangeFrom == "" && s.RangeTo > subjectName) ||
		(s.RangeTo == "" && s.RangeFrom < subjectName)
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
func sectionHasContextOrSubjectZone(section WithSig) bool {
	return section.GetSubjectZone() != "" || section.GetContext() != ""
}

//NeededKeys adds to keysNeeded key meta data which is necessary to verify all s's signatures.
func (s *Shard) NeededKeys(keysNeeded map[signature.MetaData]bool) {
	extractNeededKeys(s, keysNeeded)
	for _, a := range s.Content {
		a.NeededKeys(keysNeeded)
	}
}

func (s *Shard) AddSigInMarshaller() {
	s.sign = false
	for _, a := range s.Content {
		a.AddSigInMarshaller()
	}
}
func (s *Shard) DontAddSigInMarshaller() {
	s.sign = true
	for _, a := range s.Content {
		a.DontAddSigInMarshaller()
	}
}
