package message

import (
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

const (
	testDomain      = "example.com"
	testZone        = "com"
	testSubjectName = "example"
	globalContext   = "."
)

//GetMessage returns a messages containing all  The assertion contains an instance of every object.Types
func GetMessage() Message {
	sig := signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: algorithmTypes.Ed25519,
		},
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	assertion := &section.Assertion{
		Content:     object.AllObjects(),
		Context:     globalContext,
		SubjectName: testSubjectName,
		SubjectZone: testSubjectName,
		Signatures:  []signature.Sig{sig},
	}

	shard := &section.Shard{
		Content:     []*section.Assertion{assertion},
		Context:     globalContext,
		SubjectZone: testSubjectName,
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []signature.Sig{sig},
	}

	pshard := &section.Pshard{
		Context:     globalContext,
		SubjectZone: testSubjectName,
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []signature.Sig{sig},
	}

	zone := &section.Zone{
		Content:     []*section.Assertion{assertion},
		Context:     globalContext,
		SubjectZone: testSubjectName,
		Signatures:  []signature.Sig{sig},
	}

	q := &query.Name{
		Context:    globalContext,
		Expiration: 159159,
		Name:       testDomain,
		Options:    []query.Option{query.QOMinE2ELatency, query.QOMinInfoLeakage},
		Types:      []object.Type{object.OTIP4Addr},
	}

	notification := &section.Notification{
		Token: token.New(),
		Type:  section.NTNoAssertionsExist,
		Data:  "Notification information",
	}

	message := Message{
		Content: []section.Section{
			assertion,
			shard,
			zone,
			q,
			notification,
			pshard,
		},
		Token:        token.New(),
		Capabilities: []Capability{Capability("Test"), Capability("Yes!")},
		Signatures:   []signature.Sig{sig},
	}
	return message
}
