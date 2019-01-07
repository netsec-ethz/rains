package util

import (
	"net"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"

	"github.com/netsec-ethz/rains/internal/pkg/message"
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
	section.CheckSignatures(m1.Signatures, m2.Signatures, t)
	if len(m1.Content) != len(m2.Content) {
		t.Error("Message Content length mismatch")
	}
	for i, s1 := range m1.Content {
		switch s1 := s1.(type) {
		case *section.Assertion:
			if s2, ok := m2.Content[i].(*section.Assertion); ok {
				section.CheckAssertion(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Shard:
			if s2, ok := m2.Content[i].(*section.Shard); ok {
				section.CheckShard(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Zone:
			if s2, ok := m2.Content[i].(*section.Zone); ok {
				section.CheckZone(s1, s2, t)
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
