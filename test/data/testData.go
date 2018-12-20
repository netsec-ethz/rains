package data

import (
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/token"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"

	"golang.org/x/crypto/ed25519"
)

const (
	ip4TestAddr       = "192.0.2.0"
	ip4TestAddr2      = "198.51.100.0"
	ip4TestAddr3      = "203.0.113.0"
	ip6TestAddr       = "2001:db8::"
	ip4TestAddrCIDR24 = "192.0.2.0/24"
	ip4TestAddrCIDR32 = "192.0.2.0/32"
	ip4TestAddr2CIDR  = "198.51.100.0/24"
	ip4TestAddr3CIDR  = "203.0.113.0/24"
	ip6TestAddrCIDR   = "2001:db8::/32"
	testDomain        = "example.com"
	testZone          = "com"
	testSubjectName   = "example"
	globalContext     = "."
)

//GetMessage returns a messages containing all section. The assertion contains an instance of every objectTypes
func GetMessage() message.Message {
	sig := signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: algorithmTypes.Ed25519,
		},
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	assertion := &section.Assertion{
		Content:     AllObjects(),
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

	zone := &section.Zone{
		Content:     []section.WithSigForward{assertion, shard},
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

	message := message.Message{
		Content: []section.Section{
			assertion,
			shard,
			zone,
			q,
			notification,
		},
		Token:        token.New(),
		Capabilities: []message.Capability{message.Capability("Test"), message.Capability("Yes!")},
		Signatures:   []signature.Sig{sig},
	}
	return message
}

//Zone returns an zone containing a shard, assertion with all object types and a pshard. The zone is valid.
func Zone() *section.Zone {
	return &section.Zone{
		Content:     []section.WithSigForward{Assertion()},
		Context:     globalContext,
		SubjectZone: testDomain,
	}
}

//Shard returns a shard containing an assertion with all object types that is valid.
func Shard() *section.Shard {
	return &section.Shard{
		Content:     []*section.Assertion{Assertion()},
		Context:     globalContext,
		SubjectZone: testDomain,
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
	}
}

//Pshard returns a shard containing an assertion with all object types that is valid.
func Pshard() *section.Pshard {
	return &section.Pshard{
		Datastructure: Datastructure(),
		Context:       globalContext,
		SubjectZone:   testDomain,
		RangeFrom:     "aaa",
		RangeTo:       "zzz",
	}
}

//Assertion returns an assertion containing all objects types that is valid.
func Assertion() *section.Assertion {
	return &section.Assertion{
		Content:     AllObjects(),
		Context:     globalContext,
		SubjectName: testSubjectName,
		SubjectZone: testZone,
	}
}

//AllObjects returns all objects with valid content
func AllObjects() []object.Object {
	ip6Object := object.Object{Type: object.OTIP6Addr, Value: ip6TestAddr}
	ip4Object := object.Object{Type: object.OTIP4Addr, Value: ip4TestAddr}
	redirObject := object.Object{Type: object.OTRedirection, Value: testDomain}
	delegObject := object.Object{Type: object.OTDelegation, Value: PublicKey()}
	nameSetObject := object.Object{Type: object.OTNameset, Value: object.NamesetExpr("Would be an expression")}
	registrarObject := object.Object{Type: object.OTRegistrar, Value: "Registrar information"}
	registrantObject := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}
	infraObject := object.Object{Type: object.OTInfraKey, Value: PublicKey()}
	extraObject := object.Object{Type: object.OTExtraKey, Value: PublicKey()}
	nextKey := object.Object{Type: object.OTNextKey, Value: PublicKey()}
	return []object.Object{NameObject(), ip6Object, ip4Object, redirObject, delegObject,
		nameSetObject, CertificateObject(), ServiceObject(), registrarObject,
		registrantObject, infraObject, extraObject, nextKey}
}

//NameObject returns a name object with valid content
func NameObject() object.Object {
	nameObjectContent := object.Name{
		Name:  testDomain,
		Types: []object.Type{object.OTIP4Addr, object.OTIP6Addr},
	}
	return object.Object{Type: object.OTName, Value: nameObjectContent}
}

//CertificateObject returns a certificate object with valid content
func CertificateObject() object.Object {
	certificate := object.Certificate{
		Type:     object.PTTLS,
		HashAlgo: algorithmTypes.Sha256,
		Usage:    object.CUEndEntity,
		Data:     []byte("certData"),
	}
	return object.Object{Type: object.OTCertInfo, Value: certificate}
}

//ServiceObject returns a service information object with valid content
func ServiceObject() object.Object {
	serviceInfo := object.ServiceInfo{
		Name:     "srvName",
		Port:     49830,
		Priority: 1,
	}
	return object.Object{Type: object.OTServiceInfo, Value: serviceInfo}
}

//PublicKey returns a public key with a freshly generated public key and valid content
func PublicKey() keys.PublicKey {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	return keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			KeyPhase:  0,
			Algorithm: algorithmTypes.Ed25519,
		},
		ValidSince: 10000,
		ValidUntil: 50000,
		Key:        pubKey,
	}
}

//Datastructure returns a datastructure object with valid content
func Datastructure() section.DataStructure {
	return section.DataStructure{
		Type: section.BloomFilterType,
		Data: section.BloomFilter{
			HashFamily:       []algorithmTypes.Hash{algorithmTypes.Fnv128},
			NofHashFunctions: 10,
			ModeOfOperation:  section.KirschMitzenmacher1,
		},
	}
}

//Signature returns a signature object with all fields set except signature data.
func Signature() signature.Sig {
	return signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			KeyPhase:  1,
			Algorithm: algorithmTypes.Ed25519,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(24 * time.Hour).Unix(),
	}
}

//AllAllowedNetworkObjects returns a list of objects that are allowed for network subjectAddresses; with valid content
func AllAllowedNetworkObjects() []object.Object {
	redirObject := object.Object{Type: object.OTRedirection, Value: testDomain}
	delegObject := object.Object{Type: object.OTDelegation, Value: PublicKey()}
	registrantObject := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}
	return []object.Object{redirObject, delegObject, registrantObject}
}

//Notification returns a notification with all fields set
func Notification() *section.Notification {
	return &section.Notification{
		Token: token.New(),
		Type:  section.NTNoAssertionsExist,
		Data:  "Notification information",
	}
}

//NotificationNoData returns a notification with all fields set except data.
func NotificationNoData() *section.Notification {
	return &section.Notification{
		Token: token.New(),
		Type:  section.NTNoAssertionsExist,
	}
}

//Query returns a query with all query options set and querying all types.
func Query() *query.Name {
	return &query.Name{
		Context:    globalContext,
		Expiration: 50000,
		Name:       testDomain,
		Options:    AllQueryOptions(),
		Types:      AllObjectTypes(),
	}
}

//AllQueryOptions returns all query options
func AllQueryOptions() []query.Option {
	return []query.Option{
		query.QOCachedAnswersOnly,
		query.QOExpiredAssertionsOk,
		query.QOMinE2ELatency,
		query.QOMinInfoLeakage,
		query.QOMinLastHopAnswerSize,
		query.QONoProactiveCaching,
		query.QONoVerificationDelegation,
		query.QOTokenTracing,
	}
}

//AllObjectTypes returns all object types
func AllObjectTypes() []object.Type {
	return []object.Type{
		object.OTCertInfo,
		object.OTDelegation,
		object.OTExtraKey,
		object.OTInfraKey,
		object.OTIP4Addr,
		object.OTIP6Addr,
		object.OTName,
		object.OTNameset,
		object.OTNextKey,
		object.OTRedirection,
		object.OTRegistrant,
		object.OTRegistrar,
		object.OTServiceInfo,
	}
}
