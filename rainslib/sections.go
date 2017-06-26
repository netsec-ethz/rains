package rainslib

import (
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
	SubjectName string
	Content     []Object
	Signatures  []Signature
	SubjectZone string
	Context     string
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//Sigs return the assertion's signatures
func (a *AssertionSection) Sigs() []Signature {
	return a.Signatures
}

//AddSig adds the given signature
func (a *AssertionSection) AddSig(sig Signature) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *AssertionSection) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (a *AssertionSection) DeleteAllSigs() {
	a.Signatures = []Signature{}
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
			log.Warn("Assertion validity starts too far in the future. Drop Assertion.", "assertion", *a, "newValidSince", validSince)
			return
		}
		a.validSince = validSince
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the assertion in the cache. Validity exceeded upper bound", "assertion", *a, "newValidUntil", validUntil)
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
	return fmt.Sprintf("%s_%s_%s_%v_%v", a.Context, a.SubjectZone, a.SubjectName, a.Content, a.Signatures)
}

//EqualContextZoneName return true if the given assertion has the same context, zone, name.
func (a *AssertionSection) EqualContextZoneName(assertion *AssertionSection) bool {
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
	} else if a.SubjectName < assertion.SubjectName {
		return 1
	} else if a.SubjectZone < assertion.SubjectZone {
		return 1
	} else if a.SubjectZone > assertion.SubjectZone {
		return -1
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
		return "Assertion is nil"
	}
	return fmt.Sprintf("Assertion:[SubjectName=%s, SubjectZone=%s, Context=%s, Content=%v, Signatures:[%v]]",
		a.SubjectName, a.SubjectZone, a.Context, a.Content, a.Signatures)
}

//ShardSection contains information about the shard
type ShardSection struct {
	Content     []*AssertionSection
	Signatures  []Signature
	SubjectZone string
	Context     string
	RangeFrom   string
	RangeTo     string
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//Sigs return the shard's signatures
func (s *ShardSection) Sigs() []Signature {
	return s.Signatures
}

//AddSig adds the given signature
func (s *ShardSection) AddSig(sig Signature) {
	s.Signatures = append(s.Signatures, sig)
}

//DeleteSig deletes ith signature
func (s *ShardSection) DeleteSig(i int) {
	s.Signatures = append(s.Signatures[:i], s.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (s *ShardSection) DeleteAllSigs() {
	s.Signatures = []Signature{}
	for _, assertion := range s.Content {
		assertion.DeleteAllSigs()
	}
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
			log.Warn("Shard validity starts too far in the future. Drop Shard.", "shard", *s, "newValidSince", validSince)
			return
		}
		s.validSince = validSince
	}
	if validUntil > s.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			s.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the shard in the cache. Validity exceeded upper bound", "shard", *s, "newValidUntil", validUntil)
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
	aHashes := ""
	for _, a := range s.Content {
		aHashes += a.Hash()
	}
	return fmt.Sprintf("%s_%s_%s_%s_%s_%v", s.Context, s.SubjectZone, s.RangeFrom, s.RangeTo, aHashes, s.Signatures)
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
		return 1
	} else if s.SubjectZone > shard.SubjectZone {
		return -1
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
		return "Shard is nil"
	}
	return fmt.Sprintf("Shard:[SubjectZone=%s, Context=%s, RangeFrom=%s, RangeTo=%s, Content=%v, Signatures:[%v]]",
		s.SubjectZone, s.Context, s.RangeFrom, s.RangeTo, s.Content, s.Signatures)
}

//ZoneSection contains information about the zone
type ZoneSection struct {
	Signatures  []Signature
	SubjectZone string
	Context     string
	Content     []MessageSectionWithSig
	validSince  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
	validUntil  int64 //unit: the number of seconds elapsed since January 1, 1970 UTC
}

//Sigs return the zone's signatures
func (z *ZoneSection) Sigs() []Signature {
	return z.Signatures
}

//AddSig adds the given signature
func (z *ZoneSection) AddSig(sig Signature) {
	z.Signatures = append(z.Signatures, sig)
}

//DeleteSig deletes ith signature
func (z *ZoneSection) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (z *ZoneSection) DeleteAllSigs() {
	z.Signatures = []Signature{}
	for _, section := range z.Content {
		switch section := section.(type) {
		case *AssertionSection, *ShardSection:
			section.DeleteAllSigs()
		default:
			log.Warn("Unknown message section", "messageSection", section)
		}
	}
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
			log.Warn("Zone validity starts too far in the future. Drop Zone.", "zone", *z, "newValidSince", validSince)
			return
		}
		z.validSince = validSince
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the zone in the cache. Validity exceeded upper bound", "zone", *z, "newValidUntil", validUntil)
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
	contentHashes := ""
	for _, v := range z.Content {
		switch v := v.(type) {
		case *AssertionSection, *ShardSection:
			contentHashes += v.Hash()
		default:
			log.Warn(fmt.Sprintf("not supported zone section content, must be assertion or shard, got %T", v))
		}
	}
	return fmt.Sprintf("%s_%s_%s_%v", z.Context, z.SubjectZone, contentHashes, z.Signatures)
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
			if s, ok := z.Content[i].(*ShardSection); ok {
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
		return "Zone is nil"
	}
	return fmt.Sprintf("Zone:[SubjectZone=%s, Context=%s, Content=%v, Signatures=[%v]]",
		z.SubjectZone, z.Context, z.Content, z.Signatures)
}

//QuerySection contains information about the query
type QuerySection struct {
	//Mandatory
	Token   Token
	Name    string
	Context string
	Type    ObjectType
	Expires int64 //time when this query expires represented as the number of seconds elapsed since January 1, 1970 UTC

	//Optional
	Options []QueryOption
}

//ContainsOption returns true if the query contains the given query option.
func (q QuerySection) ContainsOption(option QueryOption) bool {
	for _, opt := range q.Options {
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
	if q.Token != query.Token {
		for i, b := range q.Token {
			if b < query.Token[i] {
				return -1
			} else if b > query.Token[i] {
				return 1
			}
		}
		log.Error("Token must be different", "t1", q.Token, "t2", query.Token)
	} else if q.Context < query.Context {
		return -1
	} else if q.Context > query.Context {
		return 1
	} else if q.Name < query.Name {
		return -1
	} else if q.Name > query.Name {
		return 1
	} else if q.Type < query.Type {
		return -1
	} else if q.Type > query.Type {
		return 1
	} else if q.Expires < query.Expires {
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

//AddressAssertionSection contains information about the address assertion
type AddressAssertionSection struct {
	SubjectAddr *net.IPNet
	Content     []Object
	Signatures  []Signature
	Context     string
	validSince  int64
	validUntil  int64
}

//Sigs return the assertion's signatures
func (a *AddressAssertionSection) Sigs() []Signature {
	return a.Signatures
}

//AddSig adds the given signature
func (a *AddressAssertionSection) AddSig(sig Signature) {
	a.Signatures = append(a.Signatures, sig)
}

//DeleteSig deletes ith signature
func (a *AddressAssertionSection) DeleteSig(i int) {
	a.Signatures = append(a.Signatures[:i], a.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (a *AddressAssertionSection) DeleteAllSigs() {
	a.Signatures = []Signature{}
}

//GetContext returns the context of the assertion
func (a *AddressAssertionSection) GetContext() string {
	return a.Context
}

//GetSubjectZone returns the zone of the shard
func (a *AddressAssertionSection) GetSubjectZone() string {
	if a.Context == "." {
		//FIXME CFE how to find out authority when delegated???
		return "."
	}
	return strings.Split(a.Context, "cx-")[1]
}

//CreateStub creates a copy of the assertion without the signatures.
func (a *AddressAssertionSection) CreateStub() MessageSectionWithSig {
	stub := &AddressAssertionSection{}
	*stub = *a
	stub.DeleteAllSigs()
	return stub
}

//UpdateValidity updates the validity of this assertion if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (a *AddressAssertionSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if a.validSince == 0 {
		a.validSince = math.MaxInt64
	}
	if validSince < a.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			log.Warn("AddressAssertion validity starts too far in the future. Drop AddressAssertion.", "addressAssertion", *a, "newValidSince", validSince)
			return
		}
		a.validSince = validSince
	}
	if validUntil > a.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			a.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the addressAssertion in the cache. Validity exceeded upper bound", "addressAssertion", *a, "newValidUntil", validUntil)
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
	return fmt.Sprintf("%s_%s_%v_%v",
		a.Context,
		a.SubjectAddr,
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
	}
	for i, o := range a.Content {
		if o.CompareTo(assertion.Content[i]) != 0 {
			return o.CompareTo(assertion.Content[i])
		}
	}
	return 0
}

//AddressZoneSection contains information about the address zone
type AddressZoneSection struct {
	SubjectAddr *net.IPNet
	Content     []*AddressAssertionSection
	Signatures  []Signature
	Context     string
	validSince  int64
	validUntil  int64
}

//Sigs return the zone's signatures
func (z *AddressZoneSection) Sigs() []Signature {
	return z.Signatures
}

//AddSig adds the given signature
func (z *AddressZoneSection) AddSig(sig Signature) {
	z.Signatures = append(z.Signatures, sig)
}

//DeleteSig deletes ith signature
func (z *AddressZoneSection) DeleteSig(i int) {
	z.Signatures = append(z.Signatures[:i], z.Signatures[i+1:]...)
}

//DeleteAllSigs deletes all signatures
func (z *AddressZoneSection) DeleteAllSigs() {
	z.Signatures = []Signature{}
	for _, assertion := range z.Content {
		assertion.DeleteAllSigs()
	}
}

//GetContext returns the context of the zone
func (z *AddressZoneSection) GetContext() string {
	return z.Context
}

//GetSubjectZone returns the zone of the shard
func (z *AddressZoneSection) GetSubjectZone() string {
	if z.Context == "." {
		//FIXME CFE how to find out authority when delegated???
		return "."
	}
	return strings.Split(z.Context, "cx-")[1]
}

//CreateStub creates a copy of the zone and the contained shards and assertions without the signatures.
func (z *AddressZoneSection) CreateStub() MessageSectionWithSig {
	stub := &AddressZoneSection{}
	*stub = *z
	stub.Content = []*AddressAssertionSection{}
	for _, assertion := range z.Content {
		stub.Content = append(stub.Content, assertion.CreateStub().(*AddressAssertionSection))
	}
	stub.DeleteAllSigs()
	return stub
}

//UpdateValidity updates the validity of this addressZone if the validity period is extended.
//It makes sure that the validity is never larger than maxValidity
func (z *AddressZoneSection) UpdateValidity(validSince, validUntil int64, maxValidity time.Duration) {
	if z.validSince == 0 {
		z.validSince = math.MaxInt64
	}
	if validSince < z.validSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			log.Warn("AddressZone validity starts too far in the future. Drop addressZone.", "addressZone", *z, "newValidSince", validSince)
			return
		}
		z.validSince = validSince
	}
	if validUntil > z.validUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			z.validUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("Limit the validity of the addressZone in the cache. Validity exceeded upper bound", "addressZone", *z, "newValidUntil", validUntil)
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
	contentHashes := ""
	for _, a := range z.Content {
		contentHashes += a.Hash()
	}
	return fmt.Sprintf("%s_%s_%s_%v",
		z.Context,
		z.SubjectAddr,
		contentHashes,
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
	}
	for i, a := range z.Content {
		if a.CompareTo(zone.Content[i]) != 0 {
			return a.CompareTo(zone.Content[i])
		}
	}
	return 0
}

//AddressQuerySection contains information about the address query
type AddressQuerySection struct {
	SubjectAddr *net.IPNet
	Token       Token
	Context     string
	Type        ObjectType
	Expires     int64
	//Optional
	Options []QueryOption
}

//ContainsOption returns true if the address query contains the given query option.
func (q AddressQuerySection) ContainsOption(option QueryOption) bool {
	for _, opt := range q.Options {
		if opt == option {
			return true
		}
	}
	return false
}

//Sort sorts the content of the addressQuery lexicographically.
func (q *AddressQuerySection) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two addressQueries and returns 0 if they are equal, 1 if q is greater than query and -1 if q is smaller than query
func (q *AddressQuerySection) CompareTo(query *AddressQuerySection) int {
	if q.Token != query.Token {
		for i, b := range q.Token {
			if b < query.Token[i] {
				return -1
			} else if b > query.Token[i] {
				return 1
			}
		}
		log.Error("Token must be different", "t1", q.Token, "t2", query.Token)
	} else if q.SubjectAddr.String() < query.SubjectAddr.String() {
		return -1
	} else if q.SubjectAddr.String() > query.SubjectAddr.String() {
		return 1
	} else if q.Context < query.Context {
		return -1
	} else if q.Context > query.Context {
		return 1
	} else if q.Type < query.Type {
		return -1
	} else if q.Type > query.Type {
		return 1
	} else if q.Expires < query.Expires {
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

//NotificationSection contains information about the notification
type NotificationSection struct {
	//Mandatory
	Token Token
	Type  NotificationType
	//Optional
	Data string
}

//Sort sorts the content of the notification lexicographically.
func (n *NotificationSection) Sort() {
	//notification is already sorted (it does not contain a list of elements).
}

//CompareTo compares two notifications and returns 0 if they are equal, 1 if n is greater than notification and -1 if n is smaller than notification
func (n *NotificationSection) CompareTo(notification *NotificationSection) int {
	if n.Type < notification.Type {
		return -1
	} else if n.Type > notification.Type {
		return 1
	} else if n.Data < notification.Data {
		return -1
	} else if n.Data > notification.Data {
		return 1
	}
	for i, b := range n.Token {
		if b < notification.Token[i] {
			return -1
		} else if b > notification.Token[i] {
			return 1
		}
	}
	return 0
}
