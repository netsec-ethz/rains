package section

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	cbor "github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

//Pshard contains information about a pshard
type Pshard struct {
	Signatures  []signature.Sig
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
	BloomFilter BloomFilter
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	sign        bool  //set to true before signing and false afterwards
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (s *Pshard) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0].([]interface{}); ok {
		s.Signatures = make([]signature.Sig, len(sigs))
		for i, sig := range sigs {
			sigVal, ok := sig.([]interface{})
			if !ok {
				return errors.New("cbor pshard signatures entry is not an array")
			}
			if err := s.Signatures[i].UnmarshalArray(sigVal); err != nil {
				return err
			}
		}
	} else {
		return errors.New("cbor pshard map does not contain a signature")
	}
	if zone, ok := m[4].(string); ok {
		s.SubjectZone = zone
	} else {
		return errors.New("cbor pshard map does not contain a subject zone")
	}
	if ctx, ok := m[6].(string); ok {
		s.Context = ctx
	} else {
		return errors.New("cbor pshard map does not contain a context")
	}
	if srange, ok := m[11].([]interface{}); ok {
		begin, ok := srange[0].(string)
		if !ok {
			return errors.New("cbor pshard encoding of rangeFrom should be a string")
		}
		s.RangeFrom = begin
		end, ok := srange[1].(string)
		if !ok {
			return errors.New("cbor pshard encoding of rangeEnd should be a string")
		}
		s.RangeTo = end
	} else {
		return errors.New("cbor pshard map does not contain a range")
	}
	if ds, ok := m[23].([]interface{}); ok {
		if err := s.BloomFilter.UnmarshalArray(ds); err != nil {
			return err
		}
	} else {
		return errors.New("cbor pshard map does not contain a bloom filter")
	}
	return nil
}

func (s *Pshard) MarshalCBOR(w *cbor.CBORWriter) error {
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
	m[23] = s.BloomFilter
	return w.WriteIntMap(m)
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

//DeleteAllSigs deletes all signature
func (s *Pshard) DeleteAllSigs() {
	s.Signatures = []signature.Sig{}
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
	s.validSince, s.validUntil = UpdateValidity(validSince, validUntil, s.validSince, s.validUntil,
		maxValidity)
}

//ValidSince returns the earliest validSince date of all contained signatures
func (s *Pshard) ValidSince() int64 {
	return s.validSince
}

//ValidUntil returns the latest validUntil date of all contained signatures
func (s *Pshard) ValidUntil() int64 {
	return s.validUntil
}

//SetValidSince sets the validSince time
func (s *Pshard) SetValidSince(validSince int64) {
	s.validSince = validSince
}

//SetValidUntil sets the validUntil time
func (s *Pshard) SetValidUntil(validUntil int64) {
	s.validUntil = validUntil
}

//Hash returns a string containing all information uniquely identifying a pshard.
func (s *Pshard) Hash() string {
	if s == nil {
		return "P_nil"
	}
	encoding := new(bytes.Buffer)
	w := cbor.NewCBORWriter(encoding)
	w.WriteArray([]interface{}{3, s})
	return encoding.String()
}

//Sort sorts the content of the pshard lexicographically.
func (s *Pshard) Sort() {
	//nothing to sort
}

//String implements Stringer interface
func (s *Pshard) String() string {
	if s == nil {
		return "Pshard:nil"
	}
	return fmt.Sprintf("Pshard:[SZ=%s CTX=%s RF=%s RT=%s BF=%v SIG=%v]",
		s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo, s.BloomFilter, s.Signatures)
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

func (s *Pshard) AddSigInMarshaller() {
	s.sign = false
}
func (s *Pshard) DontAddSigInMarshaller() {
	s.sign = true
}

//Copy creates a copy of the shard with the given context and subjectZone values. The contained
//assertions are not modified
func (s *Pshard) Copy(context, subjectZone string) *Pshard {
	stub := &Pshard{}
	*stub = *s
	stub.Context = context
	stub.SubjectZone = subjectZone
	return stub
}

//IsNonexistent returns true if all types of q do not exist. An error is returned, when q is not
//within the pshard's range or if its context and zone does not match the pshard.
func (s *Pshard) IsNonexistent(q *query.Name) (bool, error) {
	if q.Context != s.Context {
		return false, errors.New("query has different context")
	}
	if strings.HasSuffix(q.Name, s.SubjectZone) {
		return false, errors.New("query has different suffix")
	}
	name := strings.TrimSuffix(q.Name, s.SubjectZone)
	if !s.InRange(name) {
		return false, errors.New("query is not in pshard's range")
	}
	for _, t := range q.Types {
		if val, err := s.BloomFilter.Contains(name, s.SubjectZone, s.Context, t); err != nil || val {
			return false, nil
		}
	}
	return true, nil
}

//AddAssertion adds a to the s' Bloom filter. An error is returned, if a is not within s' range or
//if they have a different context or zone.
func (s *Pshard) AddAssertion(a *Assertion) error {
	if a.Context != "" && a.Context != s.Context {
		return fmt.Errorf("assertion has different context pshardCtx=%s aCtx=%s", s.Context, a.Context)
	}
	if a.SubjectZone != "" && a.SubjectZone != s.SubjectZone {
		return fmt.Errorf("assertion has different pshardZone=%s aZone=%s", s.SubjectZone, a.SubjectZone)
	}
	if !s.InRange(a.SubjectName) {
		return errors.New("assertion is not in pshard's range")
	}
	for _, o := range a.Content {
		if err := s.BloomFilter.Add(a.SubjectName, a.SubjectZone, a.Context, o.Type); err != nil {
			return err
		}
	}
	return nil
}

//CompareTo compares two pshards and returns 0 if they are equal, 1 if s is greater than pshard and
//-1 if s is smaller than pshard
func (s *Pshard) CompareTo(pshard *Pshard) int {
	if s.SubjectZone < pshard.SubjectZone {
		return -1
	} else if s.SubjectZone > pshard.SubjectZone {
		return 1
	} else if s.Context < pshard.Context {
		return -1
	} else if s.Context > pshard.Context {
		return 1
	} else if s.RangeFrom < pshard.RangeFrom {
		return -1
	} else if s.RangeFrom > pshard.RangeFrom {
		return 1
	} else if s.RangeTo < pshard.RangeTo {
		return -1
	} else if s.RangeTo > pshard.RangeTo {
		return 1
	}
	return s.BloomFilter.CompareTo(pshard.BloomFilter)
}
