package section

import (
	"fmt"
	"math"
	"time"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

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

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (s *Pshard) UnmarshalMap(m map[int]interface{}) error {
	if sigs, ok := m[0]; ok {
		s.Signatures = make([]signature.Sig, len(sigs.([]interface{})))
		for i, sig := range sigs.([]interface{}) {
			if err := s.Signatures[i].UnmarshalArray(sig.([]interface{})); err != nil {
				return err
			}
		}
	}
	if zone, ok := m[4]; ok {
		s.SubjectZone = zone.(string)
	}
	if ctx, ok := m[6]; ok {
		s.Context = ctx.(string)
	}
	if sr, ok := m[11]; ok {
		srange := sr.([]interface{})
		s.RangeFrom = srange[0].(string)
		s.RangeTo = srange[1].(string)
	}
	if ds, ok := m[18]; ok {
		if err := s.Datastructure.UnmarshalArray(ds.([]interface{})); err != nil {
			return err
		}
	}
	return nil
}

func (s *Pshard) MarshalCBOR(w *cbor.CBORWriter) error {
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
	m[18] = s.Datastructure
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
