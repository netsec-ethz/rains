package message

import (
	"bytes"
	"testing"

	cbor2 "github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

func TestCBOR(t *testing.T) {
	var tests = []struct {
		input Message
	}{
		{GetMessage()},
	}
	for i, test := range tests {
		encoding := new(bytes.Buffer)
		err := cbor.NewWriter(encoding).Marshal(&test.input)
		if err != nil {
			t.Fatalf("%d: Was not able to marshal msg, err=%s", i, err.Error())
		}
		msg := Message{}
		err = cbor.NewReader(encoding).Unmarshal(&msg)
		if err != nil {
			t.Fatalf("%d: Was not able to unmarshal msg, err=%s", i, err.Error())
		}
		CheckMessage(test.input, msg, t)
	}
}

func TestCBORErrorCases(t *testing.T) {
	encWithRainsTag := new(bytes.Buffer)
	cbor2.NewCBORWriter(encWithRainsTag).WriteTag(cbor2.CBORTag(rainsTag))
	encWithTag := new(bytes.Buffer)
	cbor2.NewCBORWriter(encWithTag).WriteTag(cbor2.CBORTag(rainsTag + 1))
	var tests = []struct {
		encoding []byte
		errMsg   string
	}{
		{[]byte("Just some nonsense data"), "failed to read tag: invalid CBOR type for typed read"},
		{encWithTag.Bytes(), "expected tag for RAINS message but got: 15309737"},
		{append(encWithRainsTag.Bytes(), []byte("Just some nonsense data")...), "failed to read map: invalid CBOR type for typed read"},
	}
	for i, test := range tests {
		encoding := bytes.NewBuffer(test.encoding)
		msg := Message{}
		err := cbor.NewReader(encoding).Unmarshal(&msg)
		if err == nil || err.Error() != test.errMsg {
			t.Fatalf("%d: Wrong error msg while unmarshal msg, expected=%s, actual=%s", i,
				test.errMsg, err.Error())
		}
	}
}

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
	if len(m1.Signatures) != len(m2.Signatures) {
		t.Error("Signature count mismatch")
	}
	for i, s1 := range m1.Signatures {
		if s1.CompareTo(m1.Signatures[i]) != 0 {
			t.Fatalf("Signatures are not equal s1=%s s2=%s", s1, m2.Signatures[i])
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
		case *section.Pshard:
			if s2, ok := m2.Content[i].(*section.Pshard); ok {
				if s1.CompareTo(s2) != 0 {
					t.Fatalf("Pshard are not equal q1=%s q2=%s", s1, s2)
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
