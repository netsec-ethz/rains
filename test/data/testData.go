package data

import (
	"net"

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

	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip4TestAddrCIDR24)
	_, subjectAddress3, _ := net.ParseCIDR(ip6TestAddrCIDR)

	assertion := &section.Assertion{
		Content:     GetAllValidObjects(),
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
		Content:     []section.SecWithSigForward{assertion, shard},
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

	addressAssertion1 := &section.AddrAssertion{
		SubjectAddr: subjectAddress1,
		Context:     globalContext,
		Content:     []object.Object{GetValidNameObject()},
		Signatures:  []signature.Sig{sig},
	}

	addressAssertion2 := &section.AddrAssertion{
		SubjectAddr: subjectAddress2,
		Context:     globalContext,
		Content:     GetAllowedNetworkObjects(),
		Signatures:  []signature.Sig{sig},
	}

	addressAssertion3 := &section.AddrAssertion{
		SubjectAddr: subjectAddress3,
		Context:     globalContext,
		Content:     GetAllowedNetworkObjects(),
		Signatures:  []signature.Sig{sig},
	}

	addressQuery := &query.Address{
		SubjectAddr: subjectAddress1,
		Context:     globalContext,
		Expiration:  7564859,
		Types:       []object.Type{object.OTName},
		Options:     []query.Option{query.QOMinE2ELatency, query.QOMinInfoLeakage},
	}

	message := message.Message{
		Content: []section.Section{
			assertion,
			shard,
			zone,
			q,
			notification,
			addressAssertion1,
			addressAssertion2,
			addressAssertion3,
			addressQuery,
		},
		Token:        token.New(),
		Capabilities: []message.Capability{message.Capability("Test"), message.Capability("Yes!")},
		Signatures:   []signature.Sig{sig},
	}
	return message
}

//GetAllValidObjects returns all objects with valid content
func GetAllValidObjects() []object.Object {

	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: algorithmTypes.Ed25519,
		},
		ValidSince: 10000,
		ValidUntil: 50000,
		Key:        pubKey,
	}
	certificate := object.Certificate{
		Type:     object.PTTLS,
		HashAlgo: algorithmTypes.Sha256,
		Usage:    object.CUEndEntity,
		Data:     []byte("certData"),
	}
	serviceInfo := object.ServiceInfo{
		Name:     "srvName",
		Port:     49830,
		Priority: 1,
	}

	nameObject := GetValidNameObject()
	ip6Object := object.Object{Type: object.OTIP6Addr, Value: ip6TestAddr}
	ip4Object := object.Object{Type: object.OTIP4Addr, Value: ip4TestAddr}
	redirObject := object.Object{Type: object.OTRedirection, Value: testDomain}
	delegObject := object.Object{Type: object.OTDelegation, Value: publicKey}
	nameSetObject := object.Object{Type: object.OTNameset, Value: object.NamesetExpr("Would be an expression")}
	certObject := object.Object{Type: object.OTCertInfo, Value: certificate}
	serviceInfoObject := object.Object{Type: object.OTServiceInfo, Value: serviceInfo}
	registrarObject := object.Object{Type: object.OTRegistrar, Value: "Registrar information"}
	registrantObject := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}
	infraObject := object.Object{Type: object.OTInfraKey, Value: publicKey}
	extraObject := object.Object{Type: object.OTExtraKey, Value: publicKey}
	nextKey := object.Object{Type: object.OTNextKey, Value: publicKey}
	return []object.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
		registrantObject, infraObject, extraObject, nextKey}
}

//GetValidNameObject returns nameObject with valid content
func GetValidNameObject() object.Object {
	nameObjectContent := object.Name{
		Name:  testDomain,
		Types: []object.Type{object.OTIP4Addr, object.OTIP6Addr},
	}
	return object.Object{Type: object.OTName, Value: nameObjectContent}
}

//GetAllowedNetworkObjects returns a list of objects that are allowed for network subjectAddresses; with valid content
func GetAllowedNetworkObjects() []object.Object {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: algorithmTypes.Ed25519,
		},
		Key:        pubKey,
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	redirObject := object.Object{Type: object.OTRedirection, Value: testDomain}
	delegObject := object.Object{Type: object.OTDelegation, Value: publicKey}
	registrantObject := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}
	return []object.Object{redirObject, delegObject, registrantObject}
}
