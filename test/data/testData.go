package data

import (
	"net"

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

//GetMessage returns a messages containing all sections. The assertion contains an instance of every objectTypes
func GetMessage() RainsMessage {
	signature := Signature{
		PublicKeyID: PublicKeyID{
			KeySpace:  RainsKeySpace,
			Algorithm: Ed25519,
		},
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip4TestAddrCIDR24)
	_, subjectAddress3, _ := net.ParseCIDR(ip6TestAddrCIDR)

	assertion := &AssertionSection{
		Content:     GetAllValidObjects(),
		Context:     globalContext,
		SubjectName: testSubjectName,
		SubjectZone: testSubjectName,
		Signatures:  []Signature{signature},
	}

	shard := &ShardSection{
		Content:     []*AssertionSection{assertion},
		Context:     globalContext,
		SubjectZone: testSubjectName,
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []Signature{signature},
	}

	zone := &ZoneSection{
		Content:     []MessageSectionWithSigForward{assertion, shard},
		Context:     globalContext,
		SubjectZone: testSubjectName,
		Signatures:  []Signature{signature},
	}

	query := &QuerySection{
		Context:    globalContext,
		Expiration: 159159,
		Name:       testDomain,
		Options:    []QueryOption{QOMinE2ELatency, QOMinInfoLeakage},
		Types:      []ObjectType{OTIP4Addr},
	}

	notification := &NotificationSection{
		Token: GenerateToken(),
		Type:  NTNoAssertionsExist,
		Data:  "Notification information",
	}

	addressAssertion1 := &AddressAssertionSection{
		SubjectAddr: subjectAddress1,
		Context:     globalContext,
		Content:     []Object{GetValidNameObject()},
		Signatures:  []Signature{signature},
	}

	addressAssertion2 := &AddressAssertionSection{
		SubjectAddr: subjectAddress2,
		Context:     globalContext,
		Content:     GetAllowedNetworkObjects(),
		Signatures:  []Signature{signature},
	}

	addressAssertion3 := &AddressAssertionSection{
		SubjectAddr: subjectAddress3,
		Context:     globalContext,
		Content:     GetAllowedNetworkObjects(),
		Signatures:  []Signature{signature},
	}

	addressZone := &AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     globalContext,
		Content:     []*AddressAssertionSection{addressAssertion1, addressAssertion2, addressAssertion3},
		Signatures:  []Signature{signature},
	}

	addressQuery := &AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     globalContext,
		Expiration:  7564859,
		Types:       []ObjectType{OTName},
		Options:     []QueryOption{QOMinE2ELatency, QOMinInfoLeakage},
	}

	message := RainsMessage{
		Content: []MessageSection{
			assertion,
			shard,
			zone,
			query,
			notification,
			addressAssertion1,
			addressAssertion2,
			addressAssertion3,
			addressZone,
			addressQuery,
		},
		Token:        GenerateToken(),
		Capabilities: []Capability{Capability("Test"), Capability("Yes!")},
		Signatures:   []Signature{signature},
	}
	return message
}

//GetAllValidObjects returns all objects with valid content
func GetAllValidObjects() []Object {

	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := PublicKey{
		PublicKeyID: PublicKeyID{
			KeySpace:  RainsKeySpace,
			Algorithm: Ed25519,
		},
		ValidSince: 10000,
		ValidUntil: 50000,
		Key:        pubKey,
	}
	certificate := CertificateObject{
		Type:     PTTLS,
		HashAlgo: Sha256,
		Usage:    CUEndEntity,
		Data:     []byte("certData"),
	}
	serviceInfo := ServiceInfo{
		Name:     "srvName",
		Port:     49830,
		Priority: 1,
	}

	nameObject := GetValidNameObject()
	ip6Object := Object{Type: OTIP6Addr, Value: ip6TestAddr}
	ip4Object := Object{Type: OTIP4Addr, Value: ip4TestAddr}
	redirObject := Object{Type: OTRedirection, Value: testDomain}
	delegObject := Object{Type: OTDelegation, Value: publicKey}
	nameSetObject := Object{Type: OTNameset, Value: NamesetExpression("Would be an expression")}
	certObject := Object{Type: OTCertInfo, Value: certificate}
	serviceInfoObject := Object{Type: OTServiceInfo, Value: serviceInfo}
	registrarObject := Object{Type: OTRegistrar, Value: "Registrar information"}
	registrantObject := Object{Type: OTRegistrant, Value: "Registrant information"}
	infraObject := Object{Type: OTInfraKey, Value: publicKey}
	extraObject := Object{Type: OTExtraKey, Value: publicKey}
	nextKey := Object{Type: OTNextKey, Value: publicKey}
	return []Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
		registrantObject, infraObject, extraObject, nextKey}
}

//GetValidNameObject returns nameObject with valid content
func GetValidNameObject() Object {
	nameObjectContent := NameObject{
		Name:  testDomain,
		Types: []ObjectType{OTIP4Addr, OTIP6Addr},
	}
	return Object{Type: OTName, Value: nameObjectContent}
}

//GetAllowedNetworkObjects returns a list of objects that are allowed for network subjectAddresses; with valid content
func GetAllowedNetworkObjects() []Object {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := PublicKey{
		PublicKeyID: PublicKeyID{
			KeySpace:  RainsKeySpace,
			Algorithm: Ed25519,
		},
		Key:        pubKey,
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	redirObject := Object{Type: OTRedirection, Value: testDomain}
	delegObject := Object{Type: OTDelegation, Value: publicKey}
	registrantObject := Object{Type: OTRegistrant, Value: "Registrant information"}
	return []Object{redirObject, delegObject, registrantObject}
}
