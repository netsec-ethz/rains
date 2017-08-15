package rainslib

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
)

//AssertionSection contains information about the assertion
type AssertionSection struct {
	Signatures  []Signature
	SubjectName string
	SubjectZone string
	Context     string
	Content     []Object
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//AllSigs returns all assertion's signatures
func (a *AssertionSection) AllSigs() []Signature {
	return a.Signatures
}

//Sigs returns a's signatures in keyspace
func (a *AssertionSection) Sigs(keySpace KeySpaceID) []Signature {
	return filterSigs(a.Signatures, keySpace)
}

//AddSig adds the given signature
func (a *AssertionSection) AddSig(sig Signature) {
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
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", a.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			a.validSince = validSince
		}
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", a.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
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
	return fmt.Sprintf("A_%s_%s_%s_%v_%v", a.SubjectName, a.SubjectZone, a.Context, a.Content, a.Signatures)
}

//EqualContextZoneName return true if the given assertion has the same context, subjectZone, subjectName.
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

//CompareTo compares two assertions and returns 0 if they are equal, 1 if a is greater than assertion and -1 if a is smaller than assertion
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

//ShardSection contains information about the shard
type ShardSection struct {
	Signatures  []Signature
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
	Content     []*AssertionSection
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//AllSigs returns the shard's signatures
func (s *ShardSection) AllSigs() []Signature {
	return s.Signatures
}

//Sigs returns s's signatures in keyspace
func (s *ShardSection) Sigs(keySpace KeySpaceID) []Signature {
	return filterSigs(s.Signatures, keySpace)
}

//AddSig adds the given signature
func (s *ShardSection) AddSig(sig Signature) {
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

//Copy creates a copy of the shard with the given context and subjectZone values. The contained assertions are not modified
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
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", s.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			s.validSince = validSince
		}
	}
	if validUntil > s.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			s.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", s.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
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
	return fmt.Sprintf("S_%s_%s_%s_%s_[%s]_%v", s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo, strings.Join(aHashes, " "), s.Signatures)
}

//Sort sorts the content of the shard lexicographically.
func (s *ShardSection) Sort() {
	for _, a := range s.Content {
		a.Sort()
	}
	sort.Slice(s.Content, func(i, j int) bool { return s.Content[i].CompareTo(s.Content[j]) < 0 })
}

//CompareTo compares two shards and returns 0 if they are equal, 1 if s is greater than shard and -1 if s is smaller than shard
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
func (s *ShardSection) AssertionsByNameAndTypes(subjectName string, types []ObjectType) []*AssertionSection {
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

//ZoneSection contains information about the zone
type ZoneSection struct {
	Signatures  []Signature
	SubjectZone string
	Context     string
	Content     []MessageSectionWithSigForward
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//AllSigs returns the zone's signatures
func (z *ZoneSection) AllSigs() []Signature {
	return z.Signatures
}

//Sigs returns z's signatures in keyspace
func (z *ZoneSection) Sigs(keySpace KeySpaceID) []Signature {
	return filterSigs(z.Signatures, keySpace)
}

//AddSig adds the given signature
func (z *ZoneSection) AddSig(sig Signature) {
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
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", z.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			z.validSince = validSince
		}
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", z.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
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
	return fmt.Sprintf("Z_%s_%s_[%s]_%v", z.SubjectZone, z.Context, strings.Join(contentHashes, " "), z.Signatures)
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

//CompareTo compares two zones and returns 0 if they are equal, 1 if z is greater than zone and -1 if z is smaller than zone
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
	return fmt.Sprintf("Zone:[SZ=%s CTX=%s CONTENT=%v SIG=%v]", z.SubjectZone, z.Context, z.Content, z.Signatures)
}

//SectionsByNameAndTypes returns all contained assertions with subjectName and at least one object
//that has a type contained in types together with all contained shards having subjectName in their
//range. It is assumed that the contained sections are sorted as for signing. The returned
//assertions and shards are pairwise distinct.
func (z *ZoneSection) SectionsByNameAndTypes(subjectName string, types []ObjectType) (
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

//QuerySection contains information about the query
type QuerySection struct {
	Context string
	Name    string
	Types   []ObjectType
	Expires int64 //time when this query expires represented as the number of seconds elapsed since January 1, 1970 UTC
	Options []QueryOption
}

//ContainsOption returns true if the query contains the given query option.
func (q QuerySection) ContainsOption(option QueryOption) bool {
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

//CompareTo compares two queries and returns 0 if they are equal, 1 if q is greater than query and -1 if q is smaller than query
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
	if q.Expires < query.Expires {
		return -1
	} else if q.Expires > query.Expires {
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
	return fmt.Sprintf("Query:[CTX=%s NA=%s TYPE=%v EXP=%d OPT=%v]", q.Context, q.Name, q.Types, q.Expires, q.Options)
}

//AddressAssertionSection contains information about the address assertion
type AddressAssertionSection struct {
	Signatures  []Signature
	SubjectAddr *net.IPNet
	Context     string
	Content     []Object
	validSince  int64
	validUntil  int64
}

//AllSigs return the assertion's signatures
func (a *AddressAssertionSection) AllSigs() []Signature {
	return a.Signatures
}

//Sigs returns a's signatures in keyspace
func (a *AddressAssertionSection) Sigs(keySpace KeySpaceID) []Signature {
	return filterSigs(a.Signatures, keySpace)
}

//AddSig adds the given signature
func (a *AddressAssertionSection) AddSig(sig Signature) {
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
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", a.validSince, "newValidSince", validSince, "maxValidity", maxValidity)

		} else {
			a.validSince = validSince
		}
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", a.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
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

//CompareTo compares two addressAssertions and returns 0 if they are equal, 1 if a is greater than assertion and -1 if a is smaller than assertion
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
	return fmt.Sprintf("AddressAssertion:[SA=%s CTX=%s CONTENT=%v SIG=%v]", a.SubjectAddr, a.Context, a.Content, a.Signatures)
}

//AddressZoneSection contains information about the address zone
type AddressZoneSection struct {
	Signatures  []Signature
	SubjectAddr *net.IPNet
	Context     string
	Content     []*AddressAssertionSection
	validSince  int64
	validUntil  int64
}

//AllSigs return the zone's signatures
func (z *AddressZoneSection) AllSigs() []Signature {
	return z.Signatures
}

//Sigs returns z's signatures in keyspace
func (z *AddressZoneSection) Sigs(keySpace KeySpaceID) []Signature {
	return filterSigs(z.Signatures, keySpace)
}

//AddSig adds the given signature
func (z *AddressZoneSection) AddSig(sig Signature) {
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
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", z.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			z.validSince = validSince
		}
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", z.validSince, "newValidSince", validSince, "maxValidity", maxValidity)
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

//CompareTo compares two addressZones and returns 0 if they are equal, 1 if z is greater than zone and -1 if z is smaller than zone
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
	return fmt.Sprintf("AddressZone:[SA=%s CTX=%s CONTENT=%v SIG=%v]", z.SubjectAddr, z.Context, z.Content, z.Signatures)
}

//AddressQuerySection contains information about the address query
type AddressQuerySection struct {
	SubjectAddr *net.IPNet
	Context     string
	Types       []ObjectType
	Expires     int64
	Options     []QueryOption
}

//ContainsOption returns true if the address query contains the given query option.
func (q AddressQuerySection) ContainsOption(option QueryOption) bool {
	return containsOption(option, q.Options)
}

//Sort sorts the content of the addressQuery lexicographically.
func (q *AddressQuerySection) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two addressQueries and returns 0 if they are equal, 1 if q is greater than query and -1 if q is smaller than query
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
	if q.Expires < query.Expires {
		return -1
	} else if q.Expires > query.Expires {
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
	return fmt.Sprintf("AddressQuery:[SA=%s CTX=%s TYPE=%v EXP=%d OPT=%v]", q.SubjectAddr, q.Context, q.Types, q.Expires, q.Options)
}

//NotificationSection contains information about the notification
type NotificationSection struct {
	Token Token
	Type  NotificationType
	Data  string
}

//Sort sorts the content of the notification lexicographically.
func (n *NotificationSection) Sort() {
	//notification is already sorted (it does not contain a list of elements).
}

//CompareTo compares two notifications and returns 0 if they are equal, 1 if n is greater than notification and -1 if n is smaller than notification
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
	return fmt.Sprintf("Notification:[TOK=%s TYPE=%d DATA=%s]", hex.EncodeToString(n.Token[:]), n.Type, n.Data)
}

//filterSigs returns only those signatures which are in the given keySpace
func filterSigs(signatures []Signature, keySpace KeySpaceID) []Signature {
	sigs := []Signature{}
	for _, sig := range signatures {
		if sig.KeySpace == keySpace {
			sigs = append(sigs, sig)
		}
	}
	return sigs
}
