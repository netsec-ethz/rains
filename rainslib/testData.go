package rainslib

import (
	"net"

	"golang.org/x/crypto/ed25519"
)

//GetMessage returns a messages containing all sections. The assertion contains an instance of every objectTypes
func GetMessage() RainsMessage {
	signature := Signature{
		KeySpace:   RainsKeySpace,
		Algorithm:  Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")
	_, subjectAddress3, _ := net.ParseCIDR("2001:db8::/32")

	assertion := &AssertionSection{
		Content:     GetAllValidObjects(),
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
		Signatures:  []Signature{signature},
	}

	shard := &ShardSection{
		Content:     []*AssertionSection{assertion},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []Signature{signature},
	}

	zone := &ZoneSection{
		Content:     []MessageSectionWithSigForward{assertion, shard},
		Context:     ".",
		SubjectZone: "ch",
		Signatures:  []Signature{signature},
	}

	query := &QuerySection{
		Context: ".",
		Expires: 159159,
		Name:    "ethz.ch",
		Options: []QueryOption{QOMinE2ELatency, QOMinInfoLeakage},
		Token:   GenerateToken(),
		Type:    OTIP4Addr,
	}

	notification := &NotificationSection{
		Token: GenerateToken(),
		Type:  NTNoAssertionsExist,
		Data:  "Notification information",
	}

	addressAssertion1 := &AddressAssertionSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []Object{GetValidNameObject()},
		Signatures:  []Signature{signature},
	}

	addressAssertion2 := &AddressAssertionSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     GetAllowedNetworkObjects(),
		Signatures:  []Signature{signature},
	}

	addressAssertion3 := &AddressAssertionSection{
		SubjectAddr: subjectAddress3,
		Context:     ".",
		Content:     GetAllowedNetworkObjects(),
		Signatures:  []Signature{signature},
	}

	addressZone := &AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*AddressAssertionSection{addressAssertion1, addressAssertion2, addressAssertion3},
		Signatures:  []Signature{signature},
	}

	addressQuery := &AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Expires:     7564859,
		Token:       GenerateToken(),
		Type:        OTName,
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
		KeySpace:   RainsKeySpace,
		Type:       Ed25519,
		Key:        pubKey,
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	certificate := CertificateObject{
		Type:     PTTLS,
		HashAlgo: Sha256,
		Usage:    CUEndEntity,
		Data:     []byte("certData"),
	}
	serviceInfo := ServiceInfo{
		Name:     "lookup",
		Port:     49830,
		Priority: 1,
	}

	nameObject := GetValidNameObject()
	ip6Object := Object{Type: OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ip4Object := Object{Type: OTIP4Addr, Value: "127.0.0.1"}
	redirObject := Object{Type: OTRedirection, Value: "ns.ethz.ch"}
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
		Name:  "ethz2.ch",
		Types: []ObjectType{OTIP4Addr, OTIP6Addr},
	}
	return Object{Type: OTName, Value: nameObjectContent}
}

//GetAllowedNetworkObjects returns a list of objects that are allowed for network subjectAddresses; with valid content
func GetAllowedNetworkObjects() []Object {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := PublicKey{
		KeySpace:   RainsKeySpace,
		Type:       Ed25519,
		Key:        pubKey,
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	redirObject := Object{Type: OTRedirection, Value: "ns.ethz.ch"}
	delegObject := Object{Type: OTDelegation, Value: publicKey}
	registrantObject := Object{Type: OTRegistrant, Value: "Registrant information"}
	return []Object{redirObject, delegObject, registrantObject}
}
