package message

import (
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

func CheckMessage(m1, m2 Message, t *testing.T) {
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
				query.CheckQuery(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Notification:
			if s2, ok := m2.Content[i].(*section.Notification); ok {
				section.CheckNotification(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		default:
			t.Errorf("Unsupported section type: %T", s1)
		}
	}
}
