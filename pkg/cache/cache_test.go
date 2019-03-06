package cache

import (
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"golang.org/x/crypto/ed25519"
)

func TestZoneCtxKey(t *testing.T) {
	var tests = []struct {
		zone    string
		context string
		output  string
	}{
		{"", "", " "},
		{"example.com", ".", "example.com ."},
	}
	for i, test := range tests {
		if zoneCtxKey(test.zone, test.context) != test.output {
			t.Errorf("%d:Wrong return value expected=%s actual=%s", i, test.output,
				zoneCtxKey(test.zone, test.context))
		}
	}
}

func getExampleDelgations(tld string) []*section.Assertion {
	a1 := &section.Assertion{
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a2 := &section.Assertion{ //same key phase as a1 but different key and validity period
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Add(25 * time.Hour).Unix(),
					ValidUntil:  time.Now().Add(48 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey2")),
				},
			},
		},
	}
	a3 := &section.Assertion{ //different keyphase, everything else the same as a1
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 1},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	//expired delegation assertion
	a4 := &section.Assertion{ //different keyphase, everything else the same as a1
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 1},
					ValidSince:  time.Now().Add(-2 * time.Hour).Unix(),
					ValidUntil:  time.Now().Add(-1 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a5 := &section.Assertion{ //different keyphase, everything else the same as a1
		SubjectName: "@",
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a1.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	a2.UpdateValidity(time.Now().Unix(), time.Now().Add(48*time.Hour).Unix(), 48*time.Hour)
	a3.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	a4.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	a5.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	return []*section.Assertion{a1, a2, a3, a4, a5}
}

func getSignatureMetaData() []signature.MetaData {
	//signature in the interval of the above public keys
	s1 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(23 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
	}
	s2 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
		ValidUntil:  time.Now().Add(30 * time.Hour).Unix(),
	}
	s3 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 1},
		ValidSince:  time.Now().Add(23 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
	}
	//signature not in the interval of the above public keys
	s4 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(-2 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(-1 * time.Hour).Unix(),
	}
	s5 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(48*time.Hour + 1).Unix(),
		ValidUntil:  time.Now().Add(50 * time.Hour).Unix(),
	}
	s6 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(24*time.Hour + 1).Unix(),
		ValidUntil:  time.Now().Add(25*time.Hour - 1).Unix(),
	}

	return []signature.MetaData{s1, s2, s3, s4, s5, s6}
}

func getAssertions() []*section.Assertion {
	s0 := &section.Assertion{
		SubjectName: "b",
		SubjectZone: "ch",
		Context:     ".",
	}
	s1 := &section.Assertion{
		SubjectName: "e",
		SubjectZone: "ch",
		Context:     ".",
	}
	s2 := &section.Assertion{
		SubjectName: "a",
		SubjectZone: "org",
		Context:     ".",
	}
	s3 := &section.Assertion{
		SubjectName: "b",
		SubjectZone: "org",
		Context:     "test-cch",
	}
	return []*section.Assertion{s0, s1, s2, s3}
}

func getShards() []*section.Shard {
	s0 := &section.Shard{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "a",
		RangeTo:     "c",
	}
	s1 := &section.Shard{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "a",
		RangeTo:     "b",
	}
	s2 := &section.Shard{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "c",
		RangeTo:     "f",
	}
	s3 := &section.Shard{
		SubjectZone: "org",
		Context:     ".",
		RangeFrom:   "c",
		RangeTo:     "z",
	}
	s4 := &section.Shard{
		SubjectZone: "net",
		Context:     ".",
		RangeFrom:   "s",
		RangeTo:     "v",
	}
	s0.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	s1.UpdateValidity(time.Now().Unix(), time.Now().Add(48*time.Hour).Unix(), 48*time.Hour)
	s2.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	s3.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	s4.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	return []*section.Shard{s0, s1, s2, s3, s4}
}

func getZones() []*section.Zone {
	s0 := &section.Zone{
		SubjectZone: "ch",
		Context:     ".",
	}
	s1 := &section.Zone{
		SubjectZone: "org",
		Context:     ".",
	}
	s2 := &section.Zone{
		SubjectZone: "org",
		Context:     "test-cch",
	}
	s0.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	s1.UpdateValidity(time.Now().Unix(), time.Now().Add(48*time.Hour).Unix(), 48*time.Hour)
	s2.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	return []*section.Zone{s0, s1, s2}
}

func getQueries() ([]util.MsgSectionSender, []section.WithSigForward) {
	a0 := &section.Assertion{
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content:     []object.Object{object.Object{Type: object.OTIP4Addr, Value: "192.0.2.0"}},
	}
	a1 := &section.Assertion{
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content:     []object.Object{object.Object{Type: object.OTIP4Addr, Value: "203.0.113.0"}},
	}
	a2 := &section.Assertion{
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content:     []object.Object{object.Object{Type: object.OTDelegation, Value: object.PublicKey()}},
	}
	s0 := &section.Shard{SubjectZone: "net", RangeFrom: "e", RangeTo: "f"}
	q0 := &query.Name{Name: "example.net", Context: ".", Types: []object.Type{2}}
	q1 := &query.Name{Name: "example.com", Context: ".", Types: []object.Type{2}}
	q2 := &query.Name{Name: "example.com", Context: ".", Types: []object.Type{5}}
	m := []util.MsgSectionSender{
		util.MsgSectionSender{Sections: []section.Section{q0}, Sender: nil, Token: token.New()},
		util.MsgSectionSender{Sections: []section.Section{q0}, Sender: nil, Token: token.New()},
		util.MsgSectionSender{Sections: []section.Section{q1}, Sender: nil, Token: token.New()},
		util.MsgSectionSender{Sections: []section.Section{q2}, Sender: nil, Token: token.New()},
	}
	return m, []section.WithSigForward{a0, a1, s0, a2}
}
