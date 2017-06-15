package protoParser

import (
	"net"
	"rains/rainslib"
	"rains/utils/testUtil"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}
	var ed25519Pkey rainslib.Ed25519PublicKey
	copy(ed25519Pkey[:], []byte("01234567890123456789012345678901"))
	publicKey := rainslib.PublicKey{
		KeySpace:   rainslib.RainsKeySpace,
		Type:       rainslib.Ed25519,
		Key:        ed25519Pkey,
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	certificate := rainslib.CertificateObject{
		Type:     rainslib.PTTLS,
		HashAlgo: rainslib.Sha256,
		Usage:    rainslib.CUEndEntity,
		Data:     []byte("certData"),
	}
	serviceInfo := rainslib.ServiceInfo{
		Name:     "lookup",
		Port:     49830,
		Priority: 1,
	}

	nameObject := rainslib.Object{Type: rainslib.OTName, Value: nameObjectContent}
	ip6Object := rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ip4Object := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	redirObject := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	nameSetObject := rainslib.Object{Type: rainslib.OTNameset, Value: rainslib.NamesetExpression("Would be an expression")}
	certObject := rainslib.Object{Type: rainslib.OTCertInfo, Value: certificate}
	serviceInfoObject := rainslib.Object{Type: rainslib.OTServiceInfo, Value: serviceInfo}
	registrarObject := rainslib.Object{Type: rainslib.OTRegistrar, Value: "Registrar information"}
	registrantObject := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}
	infraObject := rainslib.Object{Type: rainslib.OTInfraKey, Value: publicKey}
	extraObject := rainslib.Object{Type: rainslib.OTExtraKey, Value: publicKey}
	nextKey := rainslib.Object{Type: rainslib.OTNextKey, Value: publicKey}

	signature := rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")
	_, subjectAddress3, _ := net.ParseCIDR("2001:db8::/32")

	assertion := &rainslib.AssertionSection{
		Content: []rainslib.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
			registrantObject, infraObject, extraObject, nextKey},
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{signature},
	}

	shard := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{assertion},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []rainslib.Signature{signature},
	}

	zone := &rainslib.ZoneSection{
		Content:     []rainslib.MessageSectionWithSig{assertion, shard},
		Context:     ".",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{signature},
	}

	query := &rainslib.QuerySection{
		Context: ".",
		Expires: 159159,
		Name:    "ethz.ch",
		Options: []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
		Token:   rainslib.GenerateToken(),
		Type:    rainslib.OTIP4Addr,
	}

	notification := &rainslib.NotificationSection{
		Token: rainslib.GenerateToken(),
		Type:  rainslib.NoAssertionsExist,
		Data:  "Notification information",
	}

	addressAssertion1 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []rainslib.Object{nameObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressAssertion2 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []rainslib.Object{redirObject, delegObject, registrantObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressAssertion3 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress3,
		Context:     ".",
		Content:     []rainslib.Object{redirObject, delegObject, registrantObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressZone := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion1, addressAssertion2},
		Signatures:  []rainslib.Signature{signature},
	}

	addressQuery := &rainslib.AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Expires:     7564859,
		Token:       rainslib.GenerateToken(),
		Types:       rainslib.OTName,
		Options:     []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
	}

	message := rainslib.RainsMessage{
		Content: []rainslib.MessageSection{
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
		Token:        rainslib.GenerateToken(),
		Capabilities: []rainslib.Capability{rainslib.Capability("Test"), rainslib.Capability("Yes!")},
		Signatures:   []rainslib.Signature{signature},
	}

	p := ProtoParserAndFramer{}

	msg, err := p.Encode(message)
	if err != nil {
		t.Error("Failed to encode the message")
	}
	m, err := p.Decode(msg)
	if err != nil {
		t.Error("Failed to decode the message")
	}

	testUtil.CheckMessage(m, message, t)

}
