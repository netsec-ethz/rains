package zoneFileParser

import (
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

func TestEncodeObjects(t *testing.T) {
	objectsIndents, encodings := getObjectsAndEncodings()
	for i, objects := range objectsIndents.Objects {
		encodedO := encodeObjects(objects, objectsIndents.Indents[i])
		if encodedO != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedO)
		}
	}
}

func TestEncodeAssertions(t *testing.T) {
	assertions, encodings := getAssertionAndEncodings("")
	for i, assertion := range assertions {
		encodedA := encodeAssertion(assertion, assertion.Context, assertion.SubjectZone, "")
		if encodedA != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedA)
		}
	}
}

func TestEncodeShards(t *testing.T) {
	shards, encodings := getShardAndEncodings()
	for i, shard := range shards {
		encodedS := encodeShard(shard, shard.Context, shard.SubjectZone, false)
		if encodedS != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedS)
		}
	}
}

func TestEncodeZones(t *testing.T) {
	zones, encodings := getZonesAndEncodings()
	for i, zone := range zones {
		encodedZ := encodeZone(zone, false)
		if encodedZ != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedZ)
		}
	}
}

func TestEncodeAddressAssertion(t *testing.T) {
	assertions, encodings := getAddressAssertionsAndEncodings()
	for i, assertion := range assertions {
		encodedAA := encodeAddressAssertion(assertion)
		if encodedAA != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedAA)
		}
	}
}

func TestEncodeAddressZone(t *testing.T) {
	zones, encodings := getAddressZonesAndEncodings()
	for i, zone := range zones {
		encodedAZ := encodeAddressZone(zone)
		if encodedAZ != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedAZ)
		}
	}
}

func TestEncodeAddressQuery(t *testing.T) {
	queries, encodings := getAddressQueriesAndEncodings()
	for i, query := range queries {
		encodedAQ := encodeAddressQuery(query)
		if encodedAQ != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedAQ)
		}
	}
}

func TestEncodeQuery(t *testing.T) {
	queries, encodings := getQueriesAndEncodings()
	for i, query := range queries {
		encodedQ := encodeQuery(query)
		if encodedQ != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedQ)
		}
	}
}

func TestEncodeNotification(t *testing.T) {
	notifications, encodings := getNotificationsAndEncodings()
	for i, notification := range notifications {
		encodedN := encodeNotification(notification)
		if encodedN != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedN)
		}
	}
}

func TestMessageEncoding(t *testing.T) {
	/*encodingForTestUtilMessage := ""
	var tests = []struct {
		input    rainslib.RainsMessage
		encoding string
	}{
		{testUtil.GetMessage(), encodingForTestUtilMessage},
	}
	p := new(Parser)
	for _, test := range tests {
		actual := p.EncodeMessage(&test.input)
		if actual != test.encoding {
			t.Errorf("Encoding incorrect. expected=%s, actual=%s", test.encoding, actual)
		}
	}*/
}

func TestWordScanner(t *testing.T) {
	var tests = []struct {
		input      string
		scansCalls int
		lineNumber int
		text       string
	}{
		{"Hello my name", 2, 1, "my"},
		{"Hello\tmy\tname", 2, 1, "my"},
		{"Hello\tmy\nname", 2, 1, "my"},
		{"Hello my\nname", 3, 2, "name"},
		{"Hello\tmy\n\nname", 3, 3, "name"},
		{"Hello\tmy\n\nname \t\nis", 4, 4, "is"},
		{"Hello\tmy\n\nname \t\nis", 5, 5, ""},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		for i := 0; i < test.scansCalls; i++ {
			scanner.Scan()
		}
		if scanner.Text() != test.text {
			t.Errorf("Wrong test. expected=%s, actual=%s", test.text, scanner.Text())
		}
		if scanner.LineNumber() != test.lineNumber {
			t.Errorf("Line number incorrect. expected=%d, actual=%d", test.lineNumber, scanner.LineNumber())
		}
	}
}
