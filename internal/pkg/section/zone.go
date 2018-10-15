package section

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

//Zone contains information about the zone
type Zone struct {
	Signatures  []signature.Sig
	SubjectZone string
	Context     string
	Content     []WithSigForward
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	sign        bool  //set to true before signing and false afterwards
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
	// Content is an array of ShardSections and / or Assertionsection.
	if content, ok := m[23]; ok {
		z.Content = make([]WithSigForward, 0)
		for _, item := range content.([]interface{}) {
			m := item.(map[int]interface{})
			if _, ok := m[7]; ok {
				// Shard.
				ss := &Shard{}
				if err := ss.UnmarshalMap(m); err != nil {
					return fmt.Errorf("failed to unmarshal Shard map in Zone: %v", err)
				}
				z.Content = append(z.Content, ss)
			} else if _, ok := m[18]; ok {
				// Pshard.
				ps := &Pshard{}
				if err := ps.UnmarshalMap(m); err != nil {
					return fmt.Errorf("failed to unmarshal Shard map in Zone: %v", err)
				}
				z.Content = append(z.Content, ps)
			} else if _, ok := m[3]; ok {
				// Assertion.
				as := &Assertion{}
				if err := as.UnmarshalMap(m); err != nil {
					return fmt.Errorf("failed to unmarshal Assertion map in Zone: %v", err)
				}
				z.Content = append(z.Content, as)
			} else {
				log.Error("Unsupported section in zone content")
			}
		}
	} else {
		return fmt.Errorf("missing content for Zone")
	}
	return nil
}

func (z *Zone) MarshalCBOR(w *cbor.CBORWriter) error {
	m := make(map[int]interface{})
	m[23] = z.Content
	if len(z.Signatures) > 0 && !z.sign {
		m[0] = z.Signatures
	}
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

//DeleteAllSigs deletes all signature
func (z *Zone) DeleteAllSigs() {
	z.Signatures = []signature.Sig{}
}

//GetContext returns the context of the zone
func (z *Zone) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the zone of the zone
func (z *Zone) GetSubjectZone() string {
	return z.SubjectZone
}

func (z *Zone) SetContext(ctx string) {
	z.Context = ctx
}
func (z *Zone) SetSubjectZone(zone string) {
	z.SubjectZone = zone
}

func (z *Zone) AddCtxAndZoneToContent() {
	for _, s := range z.Content {
		s.SetContext(z.Context)
		s.SetSubjectZone(z.SubjectZone)
		if shard, ok := s.(*Shard); ok {
			shard.AddCtxAndZoneToContent()
		}
	}
}

func (z *Zone) RemoveCtxAndZoneFromContent() {
	for _, s := range z.Content {
		s.SetContext("")
		s.SetSubjectZone("")
		if shard, ok := s.(*Shard); ok {
			shard.RemoveCtxAndZoneFromContent()
		}
	}
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
		case *Assertion, *Shard, *Pshard:
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

//IsConsistent returns true if all contained assertions and shards are consistent
func (z *Zone) IsConsistent() bool {
	for _, section := range z.Content {
		if sectionHasContextOrSubjectZone(section) {
			log.Warn("Contained section has a subjectZone or context", "section", section)
			return false
		}
		if shard, ok := section.(*Shard); ok && !shard.IsConsistent() {
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

func (z *Zone) AddSigInMarshaller() {
	z.sign = false
	for _, s := range z.Content {
		s.AddSigInMarshaller()
	}
}
func (z *Zone) DontAddSigInMarshaller() {
	z.sign = true
	for _, s := range z.Content {
		s.DontAddSigInMarshaller()
	}
}
