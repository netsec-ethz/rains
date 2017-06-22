package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"rains/rainslib"
	"testing"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func TestEncoder(t *testing.T) {
	/*nameObjectContent := rainslib.NameObject{
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
	testUtil.CheckAssertion(compareAssertion, assertions[0], t)*/

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
	messages, encodings := getMessagesAndEncodings()
	for i, message := range messages {
		encodedM := encodeMessage(message)
		if encodedM != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedM)
		}
	}
}

func TestEncodeCapabilities(t *testing.T) {
	var tests = []struct {
		input []rainslib.Capability
		want  string
	}{
		{[]rainslib.Capability{rainslib.Capability("capa1")}, "[ capa1 ]"},
		{[]rainslib.Capability{rainslib.Capability("capa1"), rainslib.Capability("capa2")}, "[ capa1 capa2 ]"},
	}
	for _, test := range tests {
		if encodeCapabilities(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%s, actual=%s", test.want, encodeCapabilities(test.input))
		}
	}
}

func TestEncodeNameObject(t *testing.T) {
	var tests = []struct {
		input rainslib.NameObject
		want  string
	}{
		{rainslib.NameObject{
			Name: "name.ethz.ch",
			Types: []rainslib.ObjectType{
				rainslib.OTName,
				rainslib.OTIP6Addr,
				rainslib.OTIP4Addr,
				rainslib.OTRedirection,
				rainslib.OTDelegation,
				rainslib.OTNameset,
				rainslib.OTCertInfo,
				rainslib.OTServiceInfo,
				rainslib.OTRegistrar,
				rainslib.OTRegistrant,
				rainslib.OTInfraKey,
				rainslib.OTExtraKey,
				rainslib.OTNextKey,
			},
		}, "name.ethz.ch [ name ip6 ip4 redir deleg nameset cert srv regr regt infra extra next ]"},
	}
	for _, test := range tests {
		if encodeNameObject(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeNameObject(test.input))
		}
	}
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

func TestReplaceWhitespaces(t *testing.T) {
	var tests = []struct {
		input string
		want  string
	}{
		//spaces
		{"asdf", "asdf"},
		{"asdf asdf", "asdf asdf"},
		{"asdf   asdf", "asdf asdf"},
		{"   asdf asdf", "asdf asdf"},
		{"asdf asdf   ", "asdf asdf"},
		//tabs
		{"asdf\tasdf", "asdf asdf"},
		{"\tasdf\t asdf", "asdf asdf"},
		{"asdf\t\t\nasdf\t", "asdf asdf"},
		//new lines
		{"asdf \n \n asdf", "asdf asdf"},
		{"asdf   asdf", "asdf asdf"},
		{"\n \nasdf asdf", "asdf asdf"},
		{"asdf asdf \n\n \n  ", "asdf asdf"},
	}
	for _, test := range tests {
		if replaceWhitespaces(test.input) != test.want {
			t.Errorf("Whitespace replacement was incorrect. expected=%s, actual=%s", test.want, replaceWhitespaces(test.input))
		}
	}
}

func TestEncodeSection(t *testing.T) {
	assertion := &rainslib.AssertionSection{
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}},
		SubjectName: "ethz",
	}
	var tests = []struct {
		input rainslib.MessageSection
		want  string
	}{
		{assertion, ":A: ethz [ :ip4: 127.0.0.1 ]"},
	}
	p := Parser{}
	for _, test := range tests {
		if p.EncodeSection(test.input) != test.want {
			t.Errorf("parser.EncodeSection() incorrect. expected=%s, actual=%s", test.want, p.EncodeSection(test.input))
		}
	}
}

func TestEncodeMessage(t *testing.T) {
	assertion := &rainslib.AssertionSection{
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}},
		SubjectName: "ethz",
	}
	token := rainslib.GenerateToken()
	capabilities := []rainslib.Capability{rainslib.Capability("capa1"), rainslib.Capability("capa2")}
	encodedToken := hex.EncodeToString(token[:])
	message := &rainslib.RainsMessage{
		Capabilities: capabilities,
		Token:        token,
		Content:      []rainslib.MessageSection{assertion},
	}
	var tests = []struct {
		input *rainslib.RainsMessage
		want  string
	}{
		{message, fmt.Sprintf(":M: [ capa1 capa2 ] %s [ :A: ethz [ :ip4: 127.0.0.1 ] ]", encodedToken)},
	}
	p := Parser{}
	for _, test := range tests {
		if p.EncodeMessage(test.input) != test.want {
			t.Errorf("parser.EncodeSection() incorrect. expected=%s, actual=%s", test.want, p.EncodeMessage(test.input))
		}
	}
}

func TestDecodePublicKeyData(t *testing.T) {
	var tests = []struct {
		input        string
		inputKey     rainslib.PublicKey
		want         rainslib.PublicKey
		wantErrorMsg string
	}{
		{
			hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012")),
			rainslib.PublicKey{
				Key:        rainslib.RainsKeySpace,
				Type:       rainslib.Ed25519,
				ValidSince: 0,
				ValidUntil: 5},
			rainslib.PublicKey{
				KeySpace:   rainslib.RainsKeySpace,
				Type:       rainslib.Ed25519,
				Key:        ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
				ValidSince: 0,
				ValidUntil: 5},
			"",
		},
		{
			hex.EncodeToString([]byte("keyTooShort")),
			rainslib.PublicKey{
				Key:        rainslib.RainsKeySpace,
				Type:       rainslib.Ed25519,
				ValidSince: 0,
				ValidUntil: 5},
			rainslib.PublicKey{},
			"public key length is not 32. actual:11",
		},
		{
			"noEncoding",
			rainslib.PublicKey{
				Key:        rainslib.RainsKeySpace,
				Type:       rainslib.Ed25519,
				ValidSince: 0,
				ValidUntil: 5},
			rainslib.PublicKey{},
			"encoding/hex: invalid byte: U+006E 'n'",
		},
	}
	for _, test := range tests {
		pkey, err := decodePublicKeyData(test.input, test.inputKey)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("Resulting publicKey incorrect after decoding. expected=%v, actual=%v", test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeKeyAlgoType(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.SignatureAlgorithmType
		wantErrorMsg string
	}{
		{"ed25519", rainslib.Ed25519, ""},
		{"ed448", rainslib.Ed448, ""},
		{"ecdsa256", rainslib.Ecdsa256, ""},
		{"ecdsa384", rainslib.Ecdsa384, ""},
		{"FalseEncoding", rainslib.SignatureAlgorithmType(-1), "encountered non existing signature algorithm type: FalseEncoding"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		keyAlgo, err := decodeKeyAlgoType(test.input)
		if keyAlgo != test.want {
			t.Errorf("incorrect decoding of keyAlgoType. expected=%v, actual=%v", test.want, keyAlgo)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeSigAlgoAndData(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.PublicKey
		wantErrorMsg string
	}{
		{fmt.Sprintf("ed25519 %s", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))),
			rainslib.PublicKey{Type: rainslib.Ed25519, Key: ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012"))}, ""},
		{fmt.Sprintf("ed25519 %s", hex.EncodeToString([]byte("keyTooShort"))),
			rainslib.PublicKey{}, "public key length is not 32. actual:11"},
		{"ed448", rainslib.PublicKey{}, "not yet implemented"},
		{"ecdsa256", rainslib.PublicKey{}, "not yet implemented"},
		{"ecdsa384", rainslib.PublicKey{}, "not yet implemented"},
		{"noEncoding", rainslib.PublicKey{}, "encountered non existing signature algorithm type: noEncoding"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		pkey, err := decodeSigAlgoAndData(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of publicKey. expected=%v, actual=%v", test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeNextKey(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.PublicKey
		wantErrorMsg string
	}{
		{fmt.Sprintf(":next: ed25519 %s 5 10", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))),
			rainslib.PublicKey{
				Type:       rainslib.Ed25519,
				Key:        ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
				ValidSince: 5,
				ValidUntil: 10},
			"",
		},
		{"WrongType", rainslib.PublicKey{}, "ZoneFile malformed wrong object type"},
		{":next: inexistentAlgoType", rainslib.PublicKey{}, "encountered non existing signature algorithm type: inexistentAlgoType"},
		{fmt.Sprintf(":next: ed25519 %s NaN1 10", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))), rainslib.PublicKey{}, "strconv.ParseInt: parsing \"NaN1\": invalid syntax"},
		{fmt.Sprintf(":next: ed25519 %s 5 NaN2", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))), rainslib.PublicKey{}, "strconv.ParseInt: parsing \"NaN2\": invalid syntax"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		pkey, err := decodeNextKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of nextKey. expected=%v, actual=%v", test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeExternalKey(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.PublicKey
		wantErrorMsg string
	}{
		{fmt.Sprintf(":extra: rains ed25519 %s", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))),
			rainslib.PublicKey{
				KeySpace: rainslib.RainsKeySpace,
				Type:     rainslib.Ed25519,
				Key:      ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
			},
			"",
		},
		{"WrongType", rainslib.PublicKey{}, "ZoneFile malformed wrong object type"},
		{":extra: UnsupportedKeySpaceID", rainslib.PublicKey{}, "Unsupported key space type"},
		{":extra: rains inexistentAlgoType", rainslib.PublicKey{}, "encountered non existing signature algorithm type: inexistentAlgoType"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		pkey, err := decodeExternalKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of extraKey. expected=%v, actual=%v", test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeInfraKey(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.PublicKey
		wantErrorMsg string
	}{
		{fmt.Sprintf(":infra: ed25519 %s", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))),
			rainslib.PublicKey{
				Type: rainslib.Ed25519,
				Key:  ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
			},
			"",
		},
		{"WrongType", rainslib.PublicKey{}, "ZoneFile malformed wrong object type"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		pkey, err := decodeInfraKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of infraKey. expected=%v, actual=%v", test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeDelegationKey(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.PublicKey
		wantErrorMsg string
	}{
		{fmt.Sprintf(":deleg: ed25519 %s", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))),
			rainslib.PublicKey{
				KeySpace: rainslib.RainsKeySpace,
				Type:     rainslib.Ed25519,
				Key:      ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
			},
			"",
		},
		{"WrongType", rainslib.PublicKey{}, "ZoneFile malformed wrong object type"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		pkey, err := decodeDelegationKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of delegKey. expected=%v, actual=%v", test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeCertHashType(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.HashAlgorithmType
		wantErrorMsg string
	}{
		{"noHashAlgo", rainslib.NoHashAlgo, ""},
		{"sha256", rainslib.Sha256, ""},
		{"sha384", rainslib.Sha384, ""},
		{"sha512", rainslib.Sha512, ""},
		{"FalseEncoding", rainslib.HashAlgorithmType(-1), "non existing certificate hash algorithm type"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		hashAlgo, err := decodeCertHashType(test.input)
		if hashAlgo != test.want {
			t.Errorf("incorrect decoding of certHashType. expected=%v, actual=%v", test.want, hashAlgo)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeCertUsage(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.CertificateUsage
		wantErrorMsg string
	}{
		{"endEntity", rainslib.CUEndEntity, ""},
		{"trustAnchor", rainslib.CUTrustAnchor, ""},
		{"FalseEncoding", rainslib.CertificateUsage(-1), "non existing certificate usage type"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		certUsage, err := decodeCertUsage(test.input)
		if certUsage != test.want {
			t.Errorf("incorrect decoding of certUsageType. expected=%v, actual=%v", test.want, certUsage)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeCertPT(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.ProtocolType
		wantErrorMsg string
	}{
		{"unspecified", rainslib.PTUnspecified, ""},
		{"tls", rainslib.PTTLS, ""},
		{"FalseEncoding", rainslib.ProtocolType(-1), "non existing certificate protocol type"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		certPT, err := decodeCertPT(test.input)
		if certPT != test.want {
			t.Errorf("incorrect decoding of certProtocolType. expected=%v, actual=%v", test.want, certPT)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeCertObject(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.CertificateObject
		wantErrorMsg string
	}{
		{fmt.Sprintf(":cert: tls trustAnchor sha256 %s", hex.EncodeToString([]byte("CertData"))),
			rainslib.CertificateObject{
				Type:     rainslib.PTTLS,
				Usage:    rainslib.CUTrustAnchor,
				HashAlgo: rainslib.Sha256,
				Data:     []byte("CertData"),
			},
			"",
		},
		{"WrongType", rainslib.CertificateObject{}, "ZoneFile malformed wrong object type"},
		{":cert: wrongPT", rainslib.CertificateObject{}, "non existing certificate protocol type"},
		{":cert: tls wrongCU", rainslib.CertificateObject{}, "non existing certificate usage type"},
		{":cert: tls trustAnchor wrongAlgo", rainslib.CertificateObject{}, "non existing certificate hash algorithm type"},
		{":cert: tls trustAnchor sha256 noHexEncoding", rainslib.CertificateObject{}, "encoding/hex: odd length hex string"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		cert, err := decodeCertObject(scanner)
		if cert.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of delegKey. expected=%v, actual=%v", test.want, cert)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeFreeText(t *testing.T) {
	var tests = []struct {
		input string
		want  string
	}{
		{":regt: Hello my name is ]", "Hello my name is"},
		{":regt: Hello my name is :ip:", "Hello my name is"},
		{":redir: Hello my name is   ", ""}, //not finished correctly, return empty string
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		text := decodeFreeText(scanner)
		if text != test.want {
			t.Errorf("incorrect decoding of delegKey. expected=%v, actual=%v", test.want, text)
		}
	}
}

func TestDecodeServiceInfo(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.ServiceInfo
		wantErrorMsg string
	}{
		{
			":srv: ethz.ch 80 1",
			rainslib.ServiceInfo{
				Name:     "ethz.ch",
				Port:     80,
				Priority: 1,
			},
			"",
		},
		{"WrongType", rainslib.ServiceInfo{}, "ZoneFile malformed wrong object type"},
		{":srv: ethz.ch NaN1", rainslib.ServiceInfo{}, "strconv.Atoi: parsing \"NaN1\": invalid syntax"},
		{":srv: ethz.ch 80 NaN2", rainslib.ServiceInfo{}, "strconv.Atoi: parsing \"NaN2\": invalid syntax"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		srvInfo, err := decodeServiceInfo(scanner)
		if srvInfo.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of serviceInfo object. expected=%v, actual=%v", test.want, srvInfo)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeNameObject(t *testing.T) {
	var tests = []struct {
		input        string
		want         rainslib.NameObject
		wantErrorMsg string
	}{
		{
			":name: ethz.ch [ name ip6 ip4 redir deleg nameset cert srv regr regt infra extra next ]",
			rainslib.NameObject{
				Name: "ethz.ch",
				Types: []rainslib.ObjectType{
					rainslib.OTName,
					rainslib.OTIP6Addr,
					rainslib.OTIP4Addr,
					rainslib.OTRedirection,
					rainslib.OTDelegation,
					rainslib.OTNameset,
					rainslib.OTCertInfo,
					rainslib.OTServiceInfo,
					rainslib.OTRegistrar,
					rainslib.OTRegistrant,
					rainslib.OTInfraKey,
					rainslib.OTExtraKey,
					rainslib.OTNextKey,
				},
			},
			"",
		},
		{"WrongType", rainslib.NameObject{}, "ZoneFile malformed wrong object type"},
		{":name: ethz.ch NotOpenBracket", rainslib.NameObject{}, "ZoneFile malformed not open bracket"},
		{":name: ethz.ch [ NotAnObjectType", rainslib.NameObject{}, "unsupported object type"},
		{":name: ethz.ch [ cert ", rainslib.NameObject{}, "ZoneFile malformed, not a closing bracket but EOF"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		nameObject, err := decodeNameObject(scanner)
		if nameObject.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of nameObject. expected=%v, actual=%v", test.want, nameObject)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}
