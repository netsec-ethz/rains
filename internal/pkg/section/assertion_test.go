package section

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"golang.org/x/crypto/ed25519"
)

func TestAssertionCopy(t *testing.T) {
	assertion := GetAssertion()
	aCopy := assertion.Copy(assertion.Context, assertion.SubjectZone)
	checkAssertion(assertion, aCopy, t)
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
	shuffled := append([]*Assertion{}, assertions...)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].CompareTo(shuffled[j]) < 0
	})
	for i, a := range assertions {
		checkAssertion(a, shuffled[i], t)
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

func checkAssertion(a1, a2 *Assertion, t *testing.T) {
	if a1.Context != a2.Context {
		t.Errorf("Assertion Context mismatch a1.Context=%s a2.Context=%s", a1.Context, a2.Context)
	}
	if a1.SubjectZone != a2.SubjectZone {
		t.Errorf("Assertion SubjectZone mismatch a1.SubjectZone=%s a2.SubjectZone=%s", a1.SubjectZone, a2.SubjectZone)
	}
	if a1.SubjectName != a2.SubjectName {
		t.Errorf("Assertion SubjectName mismatch a1.SubjectName=%s a2.SubjectName=%s", a1.SubjectName, a2.SubjectName)
	}
	checkSignatures(a1.Signatures, a2.Signatures, t)
	checkObjects(a1.Content, a2.Content, t)
}

func checkSignatures(s1, s2 []signature.Sig, t *testing.T) {
	if len(s1) != len(s2) {
		t.Error("Signature count mismatch")
		return
	}
	for i := 0; i < len(s1); i++ {
		if s1[i].Algorithm != s2[i].Algorithm {
			t.Errorf("Signature algorithm mismatch in %d. Signature", i)
		}
		if s1[i].KeySpace != s2[i].KeySpace {
			t.Errorf("Signature KeySpace mismatch in %d. Signature", i)
		}
		if s1[i].ValidSince != s2[i].ValidSince {
			t.Errorf("Signature ValidSince mismatch in %d. Signature", i)
		}
		if s1[i].ValidUntil != s2[i].ValidUntil {
			t.Errorf("Signature ValidUntil mismatch in %d. Signature", i)
		}
		switch s1[i].Algorithm {
		case algorithmTypes.Ed25519:
			d1 := s1[i].Data.([]byte)
			d2 := s2[i].Data.([]byte)
			if len(d1) != len(d2) {
				t.Errorf("Signature data length mismatch in %d. Signature", i)
			}
			for j := 0; j < len(d1); j++ {
				if d1[j] != d2[j] {
					t.Errorf("Signature data mismatch at %d. byte in %d. Signature", j, i)
				}
			}
		}
	}
}

func checkObjects(objs1, objs2 []object.Object, t *testing.T) {
	if len(objs1) != len(objs2) {
		t.Error("Objects length mismatch")
	}
	for i, o1 := range objs1 {
		o2 := objs2[i]
		if o1.Type != o2.Type {
			t.Errorf("Object Type mismatch at position %d", i)
		}
		switch o1.Type {
		case object.OTName:
			n1 := o1.Value.(object.Name)
			n2 := o2.Value.(object.Name)
			if n1.Name != n2.Name {
				t.Errorf("Object Value name Name mismatch at position %d", i)
			}
			if len(n1.Types) != len(n2.Types) {
				t.Error("Object Value name connection length mismatch")
			}
			for j, t1 := range n1.Types {
				if t1 != n2.Types[j] {
					t.Errorf("Object Value name type mismatch at byte %d of object %d", j, i)
				}
			}
		case object.OTIP6Addr:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value IP6 mismatch at position %d", i)
			}
		case object.OTIP4Addr:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value IP4 mismatch at position %d", i)
			}
		case object.OTScionAddr6:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value scionIP6 mismatch at position %d", i)
			}
		case object.OTScionAddr4:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value scionIP4 mismatch at position %d", i)
			}
		case object.OTRedirection:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value redirection mismatch at position %d", i)
			}
		case object.OTDelegation:
			checkPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
		case object.OTNameset:
			if o1.Value.(object.NamesetExpr) != o2.Value.(object.NamesetExpr) {
				t.Errorf("Object Value nameSet mismatch at position %d  of content slice. v1=%s v2=%s", i, o1.Value, o2.Value)
			}
		case object.OTCertInfo:
			c1 := o1.Value.(object.Certificate)
			c2 := o2.Value.(object.Certificate)
			if c1.Type != c2.Type {
				t.Errorf("Object Value CertificateInfo type mismatch at position %d", i)
			}
			if c1.HashAlgo != c2.HashAlgo {
				t.Errorf("Object Value CertificateInfo HashAlgo mismatch at position %d", i)
			}
			if c1.Usage != c2.Usage {
				t.Errorf("Object Value CertificateInfo Usage mismatch at position %d", i)
			}
			if len(c1.Data) != len(c2.Data) {
				t.Errorf("Object Value CertificateInfo data length mismatch of object %d", i)
			}
			for j, b1 := range c1.Data {
				if b1 != c2.Data[j] {
					t.Errorf("Object Value CertificateInfo data mismatch at byte %d of object %d", j, i)
				}
			}
		case object.OTServiceInfo:
			s1 := o1.Value.(object.ServiceInfo)
			s2 := o2.Value.(object.ServiceInfo)
			if s1.Name != s2.Name {
				t.Errorf("Object Value service info name mismatch at position %d", i)
			}
			if s1.Port != s2.Port {
				t.Errorf("Object Value service info Port mismatch at position %d", i)
			}
			if s1.Priority != s2.Priority {
				t.Errorf("Object Value service info Priority mismatch at position %d", i)
			}
		case object.OTRegistrar:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value registrar mismatch at position %d of content slice. v1=%s v2=%s", i, o1.Value, o2.Value)
			}
		case object.OTRegistrant:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value registrant mismatch at position %d of content slice. v1=%s v2=%s", i, o1.Value, o2.Value)
			}
		case object.OTInfraKey:
			checkPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
		case object.OTExtraKey:
			checkPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
		case object.OTNextKey:
			checkPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
		default:
			t.Errorf("Unsupported object type. got=%T", o1.Type)
		}
	}
}

func checkPublicKey(p1, p2 keys.PublicKey, t *testing.T) {
	if p1.KeySpace != p2.KeySpace {
		t.Error("PublicKey KeySpace mismatch")
	}
	if p1.Algorithm != p2.Algorithm {
		t.Error("PublicKey Type mismatch")
	}
	if p1.ValidSince != p2.ValidSince {
		t.Errorf("PublicKey ValidSince mismatch. p1.ValidSince=%v p2.ValidSince=%v", p1.ValidSince, p2.ValidSince)
	}
	if p1.ValidUntil != p2.ValidUntil {
		t.Errorf("PublicKey ValidUntil mismatch. p1.ValidUntil=%v p2.ValidUntil=%v", p1.ValidUntil, p2.ValidUntil)
	}
	switch p1 := p1.Key.(type) {
	case ed25519.PublicKey:
		if p21, ok := p2.Key.(ed25519.PublicKey); ok {
			if len(p1) != len(p21) {
				t.Errorf("publickey key mismatch p1=%v != %v=p2", p1, p2)
			}
			for i := 0; i < len(p1); i++ {
				if p1[i] != p21[i] {
					t.Errorf("publickey key mismatch p1=%v != %v=p2 at position %d", p1, p2, i)
				}
			}
		} else {
			t.Errorf("publickey key type mismatch. Got Type:%T", p2.Key)
		}
	default:
		t.Errorf("Not yet supported. Got Type:%T", p1)
	}
}

func shuffleSections(sections []Section) {
	for i := len(sections) - 1; i > 0; i-- {
		j := rand.Intn(i)
		sections[i], sections[j] = sections[j], sections[i]
	}
}

func TestFQDN(t *testing.T) {
	assertion := GetAssertion()
	if assertion.FQDN() != "example.com." {
		t.Errorf("Wrong FQDN() = %s", assertion.FQDN())
	}
	assertion.SubjectName = "@"
	if assertion.FQDN() != "com." {
		t.Errorf("Wrong FQDN() = %s", assertion.FQDN())
	}
}
