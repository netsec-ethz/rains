package section

import (
	"reflect"
	"sort"
	"testing"
)

func TestShardCopy(t *testing.T) {
	shard := GetShard()
	sCopy := shard.Copy(shard.Context, shard.SubjectZone)
	CheckShard(shard, sCopy, t)
	if shard == sCopy {
		t.Error("Assertion was not copied. Pointer is still the same.")
	}
}

func TestShardInterval(t *testing.T) {
	var tests = []struct {
		input     *Shard
		wantBegin string
		wantEnd   string
	}{
		{&Shard{RangeFrom: "a", RangeTo: "z"}, "a", "z"},
		{new(Shard), "", ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.wantBegin || test.input.End() != test.wantEnd {
			t.Errorf("%d: Assertion Begin and End are not as expectedBegin=%s expectedEnd=%s actualBegin=%s actualEnd=%s", i,
				test.wantBegin, test.wantEnd, test.input.Begin(), test.input.End())
		}
	}
}

func TestShardHash(t *testing.T) {
	var tests = []struct {
		input *Shard
		want  string
	}{
		{nil, "S_nil"},
		{new(Shard), "S_____[]_[]"},
		{&Shard{SubjectZone: "zone", Context: "ctx", RangeFrom: "RB", RangeTo: "RT", Content: []*Assertion{new(Assertion)},
			Signatures: []Signature{Signature{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1000,
				ValidUntil: 2000,
				Data:       []byte("SigData")}}},
			"S_zone_ctx_RB_RT_[A____[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong shard hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestShardCompareTo(t *testing.T) {
	shards := sortedShards(5)
	var shuffled []Section
	for _, s := range shards {
		shuffled = append(shuffled, s)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Shard).CompareTo(shuffled[j].(*Shard)) < 0
	})
	for i, s := range shards {
		CheckShard(s, shuffled[i].(*Shard), t)
	}
	s1 := &Shard{}
	s2 := &Shard{Content: []*Assertion{&Assertion{}}}
	if s1.CompareTo(s2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if s2.CompareTo(s1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
}

func TestShardSort(t *testing.T) {
	var tests = []struct {
		input  []*Assertion
		sorted []*Assertion
	}{
		{
			[]*Assertion{
				&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
				&Assertion{Content: []Object{Object{Type: OTIP4Addr}, Object{Type: OTName}}},
			},
			[]*Assertion{
				&Assertion{Content: []Object{Object{Type: OTName}, Object{Type: OTIP4Addr}}},
				&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
			},
		},
	}
	for i, test := range tests {
		s := &Shard{Content: test.input}
		s.Sort()
		if !reflect.DeepEqual(s.Content, test.sorted) {
			t.Errorf("%d: Shard.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, s.Content)
		}
	}
}

func TestAssertionsByNameAndTypes(t *testing.T) {
	ss := Shard{
		Content: make([]*Assertion, 0),
	}
	as1 := &Assertion{
		SubjectName: "example",
		SubjectZone: "com.",
		Content: []Object{Object{
			Type:  OTIP4Addr,
			Value: "127.0.0.1",
		},
			Object{
				Type:  OTIP6Addr,
				Value: "::1",
			}},
	}
	as2 := &Assertion{
		SubjectName: "example",
		SubjectZone: "com.",
		Content: []Object{
			Object{
				Type:  OTRegistrant,
				Value: "John Doe",
			},
			Object{
				Type:  OTRegistrar,
				Value: "Jane Doe",
			},
		}}
	ss.Content = append(ss.Content, as1, as2)
	res1 := ss.AssertionsByNameAndTypes("example", []ObjectType{OTRegistrar, OTIP6Addr})
	expect1 := []*Assertion{as1, as2}
	if len(res1) != 2 {
		t.Errorf("expected 2 assertionsections, but got %v", len(res1))
	}
	if !reflect.DeepEqual(res1, expect1) {
		t.Errorf("mismatched returned assertionsections: got %v, want %v", res1, expect1)
	}
	res2 := ss.AssertionsByNameAndTypes("non.existant", []ObjectType{OTRegistrar, OTIP6Addr})
	if len(res2) != 0 {
		t.Errorf("expected 0 assertionsections but got %d: %v", len(res2), res2)
	}
	res3 := ss.AssertionsByNameAndTypes("example", []ObjectType{OTIP6Addr})
	expect3 := []*Assertion{as1}
	if len(res3) != 1 {
		t.Errorf("expected 1 assertinsections but got %d: %v", len(res3), res3)
	}
	if !reflect.DeepEqual(res3, expect3) {
		t.Errorf("mismatched returned assertionsections: got %v, want %v", res3, expect3)
	}
}

func TestInRange(t *testing.T) {
	ss := Shard{
		RangeFrom: "abc",
		RangeTo:   "xyz",
	}
	testMatrix := []struct {
		Input  string
		Output bool
	}{
		{
			Input:  "aaa",
			Output: false,
		},
		{
			Input:  "abc",
			Output: false,
		},
		{
			Input:  "abcdef",
			Output: true,
		},
		{
			Input:  "zzz",
			Output: false,
		},
	}
	for i, testCase := range testMatrix {
		if out := ss.InRange(testCase.Input); out != testCase.Output {
			t.Errorf("case %d: expected response of %t from InRange, but got %t with input %s",
				i, out, testCase.Output, testCase.Input)
		}
	}
}
