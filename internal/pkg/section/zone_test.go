package section

import (
	"reflect"
	"sort"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

func TestZoneInterval(t *testing.T) {
	var tests = []struct {
		input *Zone
		want  string
	}{
		{new(Zone), ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.want || test.input.End() != test.want {
			t.Errorf("%d: Assertion Begin and End are not as expected=%s actualBegin=%s actualEnd=%s", i, test.want, test.input.Begin(), test.input.End())
		}
	}
}

func TestZoneHash(t *testing.T) {
	var tests = []struct {
		input *Zone
		want  string
	}{
		{nil, "Z_nil"},
		{new(Zone), "Z___[]_[]"},
		{&Zone{SubjectZone: "zone", Context: "ctx", Content: []*Assertion{new(Assertion)},
			Signatures: []signature.Sig{signature.Sig{
				PublicKeyID: keys.PublicKeyID{
					KeySpace:  keys.RainsKeySpace,
					Algorithm: algorithmTypes.Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1000,
				ValidUntil: 2000,
				Data:       []byte("SigData")}}},
			"Z_zone_ctx_[A____[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 KP=1 data=53696744617461}]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong zone hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestZoneCompareTo(t *testing.T) {
	zones := sortedZones(5)
	var shuffled []Section
	for _, z := range zones {
		shuffled = append(shuffled, z)
	}
	shuffleSections(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].(*Zone).CompareTo(shuffled[j].(*Zone)) < 0
	})
	for i, z := range zones {
		checkZone(z, shuffled[i].(*Zone), t)
	}
	z1 := &Zone{}
	z2 := &Zone{Content: []*Assertion{&Assertion{}}}
	if z1.CompareTo(z2) != -1 {
		t.Error("Different content length are not sorted correctly")
	}
	if z2.CompareTo(z1) != 1 {
		t.Error("Different content length are not sorted correctly")
	}
}

func TestZoneSort(t *testing.T) {
	//FIXME
	var tests = []struct {
		input  []*Assertion
		sorted []*Assertion
	}{
		{},
	}
	for i, test := range tests {
		z := &Zone{Content: test.input}
		z.Sort()
		if !reflect.DeepEqual(z.Content, test.sorted) {
			t.Errorf("%d: Zone.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, z.Content)
		}
	}
}

func checkZone(z1, z2 *Zone, t *testing.T) {
	if z1.Context != z2.Context {
		t.Error("Zone context mismatch")
	}
	if z1.SubjectZone != z2.SubjectZone {
		t.Error("Zone subjectZone mismatch")
	}
	checkSignatures(z1.Signatures, z2.Signatures, t)
	if len(z1.Content) != len(z2.Content) {
		t.Error("Zone Content length mismatch")
	}
	for i, s1 := range z1.Content {
		checkAssertion(s1, z2.Content[i], t)
	}
}
