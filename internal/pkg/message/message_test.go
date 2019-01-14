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
	for i, s1 := range m1.Signatures {
		if s1 != m2.Signatures[i] {
			t.Fatalf("Assertions are not equal q1=%s q2=%s", s1, m2.Signatures[i])
		}
	}
	if len(m1.Content) != len(m2.Content) {
		t.Error("Message Content length mismatch")
	}
	for i, s1 := range m1.Content {
		switch s1 := s1.(type) {
		case *section.Assertion:
			if s2, ok := m2.Content[i].(*section.Assertion); ok {
				if s1.CompareTo(s2) != 0 {
					t.Fatalf("Assertions are not equal q1=%s q2=%s", s1, s2)
				}
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Shard:
			if s2, ok := m2.Content[i].(*section.Shard); ok {
				if s1.CompareTo(s2) != 0 {
					t.Fatalf("Shards are not equal q1=%s q2=%s", s1, s2)
				}
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Zone:
			if s2, ok := m2.Content[i].(*section.Zone); ok {
				if s1.CompareTo(s2) != 0 {
					t.Fatalf("Zones are not equal q1=%s q2=%s", s1, s2)
				}
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *query.Name:
			if s2, ok := m2.Content[i].(*query.Name); ok {
				if s1.CompareTo(s2) != 0 {
					t.Fatalf("Queries are not equal q1=%s q2=%s", s1, s2)
				}
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *section.Notification:
			if s2, ok := m2.Content[i].(*section.Notification); ok {
				if s1.CompareTo(s2) != 0 {
					t.Fatalf("Notifications are not equal q1=%s q2=%s", s1, s2)
				}
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		default:
			t.Errorf("Unsupported section type: %T", s1)
		}
	}
}
