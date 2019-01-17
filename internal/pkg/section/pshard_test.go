package section

import (
	"math/rand"
	"sort"
	"testing"
)

func TestPshardCopy(t *testing.T) {
	pshard := GetPshard()
	pCopy := pshard.Copy(pshard.Context, pshard.SubjectZone)
	checkPshard(pshard, pCopy, t)
	if pshard == pCopy {
		t.Error("Pshard was not copied. Pointer is still the same.")
	}
}

func TestPshardInterval(t *testing.T) {
	var tests = []struct {
		input     *Pshard
		wantBegin string
		wantEnd   string
	}{
		{&Pshard{RangeFrom: "a", RangeTo: "z"}, "a", "z"},
		{new(Pshard), "", ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.wantBegin || test.input.End() != test.wantEnd {
			t.Errorf("%d: Pshard Begin and End are not as expectedBegin=%s expectedEnd=%s actualBegin=%s actualEnd=%s", i,
				test.wantBegin, test.wantEnd, test.input.Begin(), test.input.End())
		}
	}
}

func TestPshardCompareTo(t *testing.T) {
	pshards := sortedPshards(4)
	shuffled := append([]*Pshard{}, pshards...)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].CompareTo(shuffled[j]) < 0
	})
	for i, s := range pshards {
		checkPshard(s, shuffled[i], t)
	}
}

func TestPshardInRange(t *testing.T) {
	ss := Pshard{
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

func checkPshard(s1, s2 *Pshard, t *testing.T) {
	if s1.Context != s2.Context {
		t.Error("Pshard context mismatch")
	}
	if s1.SubjectZone != s2.SubjectZone {
		t.Error("Pshard subjectZone mismatch")
	}
	if s1.RangeFrom != s2.RangeFrom {
		t.Error("Pshard RangeFrom mismatch")
	}
	if s1.RangeTo != s2.RangeTo {
		t.Error("Pshard RangeTo mismatch")
	}
	checkSignatures(s1.Signatures, s2.Signatures, t)
	if s1.BloomFilter.CompareTo(s2.BloomFilter) != 0 {
		t.Error("Pshard Bloomfilter mismatch")
	}
}
