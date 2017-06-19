package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"rains/rainslib"
	"rains/utils/testUtil"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestEncoder(t *testing.T) {
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := rainslib.PublicKey{
		KeySpace: rainslib.RainsKeySpace,
		Type:     rainslib.Ed25519,
		Key:      pubKey,
	}
	publicKeyWithValidity := rainslib.PublicKey{
		KeySpace:   rainslib.RainsKeySpace,
		Type:       rainslib.Ed25519,
		Key:        pubKey,
		ValidSince: 1000,
		ValidUntil: 20000,
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
	nextKey := rainslib.Object{Type: rainslib.OTNextKey, Value: publicKeyWithValidity}

	signature := rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	containedAssertion := &rainslib.AssertionSection{
		Content: []rainslib.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
			registrantObject, infraObject, extraObject, nextKey},
		Context:     "",
		SubjectName: "ethz",
		SubjectZone: "",
		Signatures:  []rainslib.Signature{signature},
	}

	shard := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{containedAssertion},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []rainslib.Signature{signature},
	}

	zone := &rainslib.ZoneSection{
		Content:     []rainslib.MessageSectionWithSig{containedAssertion, shard},
		Context:     ".",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{signature},
	}

	parser := Parser{}
	zoneFile := parser.Encode(zone)
	fmt.Println(zoneFile)
	assertions, err := parser.Decode([]byte(zoneFile), "generatedInTest")
	if err != nil {
		t.Error(err)
	}

	compareAssertion := &rainslib.AssertionSection{
		Content: []rainslib.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
			registrantObject, infraObject, extraObject, nextKey},
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
		//no signature is decoded it is generated in rainspub
	}
	testUtil.CheckAssertion(compareAssertion, assertions[0], t)

}

func TestEncodeAddressAssertion(t *testing.T) {
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}
	publicKey := rainslib.PublicKey{
		KeySpace:   rainslib.RainsKeySpace,
		Type:       rainslib.Ed25519,
		Key:        ed25519.PublicKey([]byte("01234567890123456789012345678901")),
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	nameObject := rainslib.Object{Type: rainslib.OTName, Value: nameObjectContent}
	redirObject := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	registrantObject := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}

	signature := rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")
	_, subjectAddress3, _ := net.ParseCIDR("2001:db8::/128")
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
		Content:     []rainslib.Object{nameObject},
		Signatures:  []rainslib.Signature{signature},
	}
	encodedAA1 := encodeAddressAssertion(addressAssertion1)
	if encodedAA1 != ":AA: . ip4 127.0.0.1/32 [ :name:     ethz2.ch [ ip4 ip6 ] ]" {
		t.Errorf("Encoding wrong. expected=:AA: . ip4 127.0.0.1/32 [ :name:     ethz2.ch [ ip4 ip6 ] ] actual=%s", encodedAA1)
	}
	encodedAA2 := encodeAddressAssertion(addressAssertion2)
	if encodedAA2 != ":AA: . ip4 127.0.0.0/24 [ :redir:    ns.ethz.ch\n:deleg:    ed25519 3031323334353637383930313233343536373839303132333435363738393031\n:regt:     Registrant information ]" {
		t.Errorf("Encoding wrong. expected=:AA: . ip4 127.0.0.0/24 [ :redir:    ns.ethz.ch\n:deleg:    ed25519 3031323334353637383930313233343536373839303132333435363738393031\n:regt:     Registrant information ] actual=%s", encodedAA2)
	}
	encodedAA3 := encodeAddressAssertion(addressAssertion3)
	if encodedAA3 != ":AA: . ip6 20010db8000000000000000000000000/128 [ :name:     ethz2.ch [ ip4 ip6 ] ]" {
		t.Errorf("Encoding wrong. expected=:AA: . ip6 20010db8000000000000000000000000/128 [ :name:     ethz2.ch [ ip4 ip6 ] ] actual=%s", encodedAA3)
	}
}

func TestEncodeAddressZone(t *testing.T) {
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}
	publicKey := rainslib.PublicKey{
		KeySpace:   rainslib.RainsKeySpace,
		Type:       rainslib.Ed25519,
		Key:        ed25519.PublicKey([]byte("01234567890123456789012345678901")),
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	nameObject := rainslib.Object{Type: rainslib.OTName, Value: nameObjectContent}
	redirObject := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	registrantObject := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}

	signature := rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")
	_, subjectAddress3, _ := net.ParseCIDR("2001:db8::/128")
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
		Content:     []rainslib.Object{nameObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressZone := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion1, addressAssertion2, addressAssertion3},
		Signatures:  []rainslib.Signature{signature},
	}

	encodedAZ := encodeAddressZone(addressZone)
	if encodedAZ != ":AZ: . ip4 127.0.0.0/24 [ :AA: . ip4 127.0.0.1/32 [ :name:     ethz2.ch [ ip4 ip6 ] ] :AA: . ip4 127.0.0.0/24 [ :redir:    ns.ethz.ch\n:deleg:    ed25519 3031323334353637383930313233343536373839303132333435363738393031\n:regt:     Registrant information ] :AA: . ip6 20010db8000000000000000000000000/128 [ :name:     ethz2.ch [ ip4 ip6 ] ] ]" {
		t.Errorf("Encoding wrong. expected=:AZ: . ip4 127.0.0.0/24 [ :AA: . ip4 127.0.0.1/32 [ :name:     ethz2.ch [ ip4 ip6 ] ] :AA: . ip4 127.0.0.0/24 [ :redir:    ns.ethz.ch\n:deleg:    ed25519 3031323334353637383930313233343536373839303132333435363738393031\n:regt:     Registrant information ] :AA: . ip6 20010db8000000000000000000000000/128 [ :name:     ethz2.ch [ ip4 ip6 ] ] ] actual=%s", encodedAZ)
	}
}

func TestEncodeAddressQuery(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	token := rainslib.GenerateToken()
	encodedToken := hex.EncodeToString(token[:])
	addressQuery := &rainslib.AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Expires:     7564859,
		Token:       token,
		Types:       rainslib.OTName,
		Options:     []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
	}
	encodedAQ := encodeAddressQuery(addressQuery)
	if encodedAQ != fmt.Sprintf(":AQ: %s . ip4 127.0.0.1/32 [ 1 ] 7564859 [ 1 3 ]", encodedToken) {
		t.Errorf("Encoding wrong. expected=:AQ: %s . ip4 127.0.0.1/32 [ 1 ] 7564859 [ 1 3 ] actual=%s", encodedToken, encodedAQ)
	}
}

func TestEncodeQuery(t *testing.T) {
	token := rainslib.GenerateToken()
	encodedToken := hex.EncodeToString(token[:])
	query := &rainslib.QuerySection{
		Context: ".",
		Expires: 159159,
		Name:    "ethz.ch",
		Options: []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
		Token:   token,
		Type:    rainslib.OTIP4Addr,
	}
	encodedQ := encodeQuery(query)
	if encodedQ != fmt.Sprintf(":Q: %s . ethz.ch [ 3 ] 159159 [ 1 3 ]", encodedToken) {
		t.Errorf("Encoding wrong. expected=:Q: %s . ethz.ch [ 3 ] 159159 [ 1 3 ] actual=%s", encodedToken, encodedQ)
	}
}

func TestEncodeNotification(t *testing.T) {
	token := rainslib.GenerateToken()
	encodedToken := hex.EncodeToString(token[:])
	notification := &rainslib.NotificationSection{
		Token: token,
		Type:  rainslib.NoAssertionsExist,
		Data:  "Notification information",
	}
	encodedN := encodeNotification(notification)
	if encodedN != fmt.Sprintf(":N: %s 404 Notification information", encodedToken) {
		t.Errorf("Encoding wrong. expected=:N: %s 404 Notification information actual=%s", encodedToken, encodedN)
	}
}
