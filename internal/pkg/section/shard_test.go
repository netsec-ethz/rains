package section

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

func TestShardCopy(t *testing.T) {
	shard := GetShard()
	sCopy := shard.Copy(shard.Context, shard.SubjectZone)
	checkShard(shard, sCopy, t)
	if shard == sCopy {
		t.Error("Shard was not copied. Pointer is still the same.")
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
			t.Errorf("%d: Shard Begin and End are not as expectedBegin=%s expectedEnd=%s actualBegin=%s actualEnd=%s", i,
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
			Signatures: []signature.Sig{signature.Sig{
				PublicKeyID: keys.PublicKeyID{
					KeySpace:  keys.RainsKeySpace,
					Algorithm: algorithmTypes.Ed25519,
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
	shuffled := append([]*Shard{}, shards...)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].CompareTo(shuffled[j]) < 0
	})
	for i, s := range shards {
		checkShard(s, shuffled[i], t)
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
	//FIXME
	var tests = []struct {
		input  []*Assertion
		sorted []*Assertion
	}{
		{},
	}
	for i, test := range tests {
		s := &Shard{Content: test.input}
		s.Sort()
		if !reflect.DeepEqual(s.Content, test.sorted) {
			t.Errorf("%d: Shard.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, s.Content)
		}
	}
}

func TestShardInRange(t *testing.T) {
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

func TestShardIsConsistent(t *testing.T) {
	testMatrix := []struct {
		section    *Shard
		wellformed bool
	}{
		{new(Shard), true},
		{&Shard{Content: []*Assertion{&Assertion{SubjectZone: "zone"}}}, false},
		{&Shard{Content: []*Assertion{&Assertion{Context: "ctx"}}}, false},
		{
			section:    &Shard{SubjectZone: "legitimate.zone"},
			wellformed: true,
		},
		{
			section: &Shard{
				SubjectZone: "legitimate.zone",
				RangeFrom:   "abc",
				RangeTo:     "xyz",
				Content: []*Assertion{
					&Assertion{
						SubjectName: "aaa",
					},
				},
			},
			wellformed: false,
		},
		{
			section: &Shard{
				SubjectZone: "legitimate.zone",
				RangeFrom:   "abc",
				RangeTo:     "xyz",
				Content: []*Assertion{
					&Assertion{
						SubjectName: "def",
					},
				},
			},
			wellformed: true,
		},
		{
			section: &Shard{
				SubjectZone: "legitimate.zone",
				RangeFrom:   "abc",
				RangeTo:     "xyz",
			},
			wellformed: true,
		},
	}
	for i, testCase := range testMatrix {
		if res := testCase.section.IsConsistent(); res != testCase.wellformed {
			t.Errorf("case %d: wrong consistency: got %t, want %t", i, res, testCase.wellformed)
		}
	}
}

func checkShard(s1, s2 *Shard, t *testing.T) {
	if s1.Context != s2.Context {
		t.Error("Shard context mismatch")
	}
	if s1.SubjectZone != s2.SubjectZone {
		t.Error("Shard subjectZone mismatch")
	}
	if s1.RangeFrom != s2.RangeFrom {
		t.Error("Shard RangeFrom mismatch")
	}
	if s1.RangeTo != s2.RangeTo {
		t.Error("Shard RangeTo mismatch")
	}
	checkSignatures(s1.Signatures, s2.Signatures, t)
	if len(s1.Content) != len(s2.Content) {
		t.Error("Shard Content length mismatch")
	}
	for i, a1 := range s1.Content {
		checkAssertion(a1, s2.Content[i], t)
	}
}
