package section

import (
	"reflect"
	"sort"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

func TestAssertionCopy(t *testing.T) {
	assertion := GetAssertion()
	aCopy := assertion.Copy(assertion.Context, assertion.SubjectZone)
	CheckAssertion(assertion, aCopy, t)
	if assertion == aCopy {
		t.Error("Assertion was not copied. Pointer is still the same.")
	}
}

func TestAssertionInterval(t *testing.T) {
	var tests = []struct {
		input *Assertion
		want  string
	}{
		{&Assertion{SubjectName: "test"}, "test"},
		{new(Assertion), ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.want || test.input.End() != test.want {
			t.Errorf("%d: Assertion Begin and End are not as expected=%s actualBegin=%s actualEnd=%s", i, test.want, test.input.Begin(), test.input.End())
		}
	}
}

func TestAssertionHash(t *testing.T) {
	var tests = []struct {
		input *Assertion
		want  string
	}{
		{nil, "A_nil"},
		{new(Assertion), "A____[]_[]"},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx", Content: object.AllObjects()[:3],
			Signatures: []signature.Sig{signature.Sig{PublicKeyID: keys.PublicKeyID{KeySpace: keys.RainsKeySpace, Algorithm: algorithmTypes.Ed25519}, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"A_name_zone_ctx_[OT:1 OV:{example.com [3 2]} OT:2 OV:2001:db8:: OT:3 OV:192.0.2.0]_[{KS=0 AT=1 VS=1000 VU=2000 KP=0 data=53696744617461}]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong assertion hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestEqualContextZoneName(t *testing.T) {
	var tests = []struct {
		input *Assertion
		param *Assertion
		want  bool
	}{
		{new(Assertion), nil, false},
		{new(Assertion), new(Assertion), true},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"}, new(Assertion), false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"}, true},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "diffname", SubjectZone: "zone", Context: "ctx"}, false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "name", SubjectZone: "diffzone", Context: "ctx"}, false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "diffctx"}, false},
		{&Assertion{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&Assertion{SubjectName: "diffname", SubjectZone: "diffzone", Context: "diffctx"}, false},
	}
	for i, test := range tests {
		if test.input.EqualContextZoneName(test.param) != test.want {
			t.Errorf("%d: EqualContextZoneName() returns incorrect result. expected=%v, actual=%v", i, test.want, test.input.EqualContextZoneName(test.param))
		}
	}
}

func TestAssertionCompareTo(t *testing.T) {
	assertions := sortedAssertions(10)
	var shuffled []Section
	for _, a := range assertions {
		shuffled = append(shuffled, a)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Assertion).CompareTo(shuffled[j].(*Assertion)) < 0
	})
	for i, a := range assertions {
		CheckAssertion(a, shuffled[i].(*Assertion), t)
	}
	a1 := &Assertion{}
	a2 := &Assertion{Content: []object.Object{object.Object{}}}
	if a1.CompareTo(a2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if a2.CompareTo(a1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
}

func TestAssertionSort(t *testing.T) {
	var tests = []struct {
		input  []object.Object
		sorted []object.Object
	}{
		{
			[]object.Object{object.Object{Type: object.OTIP4Addr, Value: "192.0.2.0"}, object.Object{Type: object.OTName, Value: object.Name{Name: "name", Types: []object.Type{object.OTDelegation, object.OTName}}}},
			[]object.Object{object.Object{Type: object.OTName, Value: object.Name{Name: "name", Types: []object.Type{object.OTName, object.OTDelegation}}}, object.Object{Type: object.OTIP4Addr, Value: "192.0.2.0"}},
		},
	}
	for i, test := range tests {
		a := &Assertion{Content: test.input}
		a.Sort()
		if !reflect.DeepEqual(a.Content, test.sorted) {
			t.Errorf("%d: Assertion.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, a.Content)
		}
	}
}
