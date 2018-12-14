package util

import (
	"net"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"golang.org/x/crypto/ed25519"
)

//CFE To compare recursively if two structs contain the same elements one can use reflect.DeepEqual(x,y interface{}) bool.
//Unfortunately the function does not return which element(s) are not equal. We want this in a test scenario.

func CheckMessage(m1, m2 message.Message, t *testing.T) {
	if m1.Token != m2.Token {
		t.Error("Token mismatch")
	}
	if len(m1.Capabilities) != len(m2.Capabilities) {
		t.Error("Capabilities mismatch")
	}
	for i := 0; i < len(m1.Capabilities); i++ {
		if m1.Capabilities[i] != m2.Capabilities[i] {
			t.Error("Capabilities mismatch")
		}
	}
	CheckSignatures(m1.Signatures, m2.Signatures, t)
	if len(m1.Content) != len(m2.Content) {
		t.Error("Message Content length mismatch")
	}
	for i, s1 := range m1.Content {
		switch s1 := s1.(type) {
		case *section.Assertion:
			if s2, ok := m2.Content[i].(*section.Assertion); ok {
				CheckAssertion(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Shard:
			if s2, ok := m2.Content[i].(*section.Shard); ok {
				CheckShard(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Zone:
			if s2, ok := m2.Content[i].(*section.Zone); ok {
				CheckZone(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *query.Name:
			if s2, ok := m2.Content[i].(*query.Name); ok {
				CheckQuery(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Notification:
			if s2, ok := m2.Content[i].(*section.Notification); ok {
				CheckNotification(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		default:
			t.Errorf("Unsupported section type: %T", s1)
		}
	}
}

func CheckSignatures(s1, s2 []signature.Sig, t *testing.T) {
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

func CheckAssertion(a1, a2 *section.Assertion, t *testing.T) {
	if a1.Context != a2.Context {
		t.Errorf("Assertion Context mismatch a1.Context=%s a2.Context=%s", a1.Context, a2.Context)
	}
	if a1.SubjectZone != a2.SubjectZone {
		t.Errorf("Assertion SubjectZone mismatch a1.SubjectZone=%s a2.SubjectZone=%s", a1.SubjectZone, a2.SubjectZone)
	}
	if a1.SubjectName != a2.SubjectName {
		t.Errorf("Assertion SubjectName mismatch a1.SubjectName=%s a2.SubjectName=%s", a1.SubjectName, a2.SubjectName)
	}
	CheckSignatures(a1.Signatures, a2.Signatures, t)
	CheckObjects(a1.Content, a2.Content, t)
}

func CheckShard(s1, s2 *section.Shard, t *testing.T) {
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
	CheckSignatures(s1.Signatures, s2.Signatures, t)
	if len(s1.Content) != len(s2.Content) {
		t.Error("Shard Content length mismatch")
	}
	for i, a1 := range s1.Content {
		CheckAssertion(a1, s2.Content[i], t)
	}
}

func CheckZone(z1, z2 *section.Zone, t *testing.T) {
	if z1.Context != z2.Context {
		t.Error("Zone context mismatch")
	}
	if z1.SubjectZone != z2.SubjectZone {
		t.Error("Zone subjectZone mismatch")
	}
	CheckSignatures(z1.Signatures, z2.Signatures, t)
	if len(z1.Content) != len(z2.Content) {
		t.Error("Zone Content length mismatch")
	}
	for i, s1 := range z1.Content {
		switch s1 := s1.(type) {
		case *section.Assertion:
			if s2, ok := z2.Content[i].(*section.Assertion); ok {
				CheckAssertion(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Shard:
			if s2, ok := z2.Content[i].(*section.Shard); ok {
				CheckShard(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		default:
			t.Errorf("Unsupported section type: %T", s1)
		}
	}
}

func CheckQuery(q1, q2 *query.Name, t *testing.T) {
	if q1.Context != q2.Context {
		t.Error("Query context mismatch")
	}
	if q1.Expiration != q2.Expiration {
		t.Error("Query Expires mismatch")
	}
	if q1.Name != q2.Name {
		t.Error("Query Name mismatch")
	}
	if len(q1.Types) != len(q2.Types) {
		t.Error("Query Type length mismatch")
	}
	for i, o1 := range q1.Types {
		if o1 != q2.Types[i] {
			t.Errorf("Query Type at position %d mismatch", i)
		}
	}
	if len(q1.Options) != len(q2.Options) {
		t.Error("Query Option length mismatch")
	}
	for i, o1 := range q1.Options {
		if o1 != q2.Options[i] {
			t.Errorf("Query Option at position %d mismatch", i)
		}
	}
}

func CheckNotification(n1, n2 *section.Notification, t *testing.T) {
	if n1.Type != n2.Type {
		t.Error("Notification Type mismatch")
	}
	if n1.Token != n2.Token {
		t.Error("Notification Token mismatch")
	}
	if n1.Data != n2.Data {
		t.Error("Notification Data mismatch")
	}
}

func CheckSubjectAddress(a1, a2 *net.IPNet, t *testing.T) {
	if a1.String() != a2.String() {
		t.Error("SubjectAddr mismatch")
	}
}

func CheckObjects(objs1, objs2 []object.Object, t *testing.T) {
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
		case object.OTRedirection:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value redirection mismatch at position %d", i)
			}
		case object.OTDelegation:
			CheckPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
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
			CheckPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
		case object.OTExtraKey:
			CheckPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
		case object.OTNextKey:
			CheckPublicKey(o1.Value.(keys.PublicKey), o2.Value.(keys.PublicKey), t)
		default:
			t.Errorf("Unsupported object type. got=%T", o1.Type)
		}
	}
}

func CheckPublicKey(p1, p2 keys.PublicKey, t *testing.T) {
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
