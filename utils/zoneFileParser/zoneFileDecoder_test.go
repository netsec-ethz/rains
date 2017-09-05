package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

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
				PublicKeyID: rainslib.PublicKeyID{
					KeySpace:  rainslib.RainsKeySpace,
					Algorithm: rainslib.Ed25519,
				},
				ValidSince: 0,
				ValidUntil: 5},
			rainslib.PublicKey{
				PublicKeyID: rainslib.PublicKeyID{
					KeySpace:  rainslib.RainsKeySpace,
					Algorithm: rainslib.Ed25519,
				},
				Key:        ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
				ValidSince: 0,
				ValidUntil: 5},
			"",
		},
		{
			hex.EncodeToString([]byte("keyTooShort")),
			rainslib.PublicKey{
				PublicKeyID: rainslib.PublicKeyID{
					KeySpace:  rainslib.RainsKeySpace,
					Algorithm: rainslib.Ed25519,
				},
				ValidSince: 0,
				ValidUntil: 5},
			rainslib.PublicKey{},
			"public key length is not 32. actual:11",
		},
		{
			"noEncoding",
			rainslib.PublicKey{
				PublicKeyID: rainslib.PublicKeyID{
					KeySpace:  rainslib.RainsKeySpace,
					Algorithm: rainslib.Ed25519,
				},
				ValidSince: 0,
				ValidUntil: 5},
			rainslib.PublicKey{},
			"encoding/hex: invalid byte: U+006E 'n'",
		},
	}
	for _, test := range tests {
		pkey, err := decodeEd25519PublicKeyData(test.input, test.inputKey)
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
		{"FalseEncoding", rainslib.SignatureAlgorithmType(-1), "non existing signature algorithm type: FalseEncoding"},
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
			rainslib.PublicKey{PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519}, Key: ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012"))}, ""},
		{fmt.Sprintf("ed25519 %s", hex.EncodeToString([]byte("keyTooShort"))),
			rainslib.PublicKey{}, "public key length is not 32. actual:11"},
		{"ed448", rainslib.PublicKey{}, "not yet implemented"},
		{"ecdsa256", rainslib.PublicKey{}, "not yet implemented"},
		{"ecdsa384", rainslib.PublicKey{}, "not yet implemented"},
		{"noEncoding", rainslib.PublicKey{}, "non existing signature algorithm type: noEncoding"},
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
				PublicKeyID: rainslib.PublicKeyID{
					Algorithm: rainslib.Ed25519,
				},
				Key:        ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
				ValidSince: 5,
				ValidUntil: 10},
			"",
		},
		{"WrongType", rainslib.PublicKey{}, "ZoneFile malformed wrong object type"},
		{":next: inexistentAlgoType", rainslib.PublicKey{}, "non existing signature algorithm type: inexistentAlgoType"},
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
				PublicKeyID: rainslib.PublicKeyID{
					KeySpace:  rainslib.RainsKeySpace,
					Algorithm: rainslib.Ed25519,
				},
				Key: ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
			},
			"",
		},
		{"WrongType", rainslib.PublicKey{}, "ZoneFile malformed wrong object type"},
		{":extra: UnsupportedKeySpaceID", rainslib.PublicKey{}, "Unsupported key space type"},
		{":extra: rains inexistentAlgoType", rainslib.PublicKey{}, "non existing signature algorithm type: inexistentAlgoType"},
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
				PublicKeyID: rainslib.PublicKeyID{
					Algorithm: rainslib.Ed25519,
				},
				Key: ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
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
				PublicKeyID: rainslib.PublicKeyID{
					KeySpace:  rainslib.RainsKeySpace,
					Algorithm: rainslib.Ed25519,
				},
				Key: ed25519.PublicKey([]byte("KeyDataOfLength32 90123456789012")),
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

func TestDecodeObjects(t *testing.T) {
	objects, objectEncodings := getObjectsAndEncodings()
	var tests = []struct {
		input        string
		want         []rainslib.Object
		wantErrorMsg string
	}{
		{objectEncodings[0] + " ]", objects.Objects[0], ""},
		{"WrongType", nil, "ZoneFile malformed unsupported objectType"},
		{":ip4: 127.0.0.1 ", nil, "ZoneFile malformed, not a closing bracket but EOF"},
		{":name: name NotABracket", nil, "ZoneFile malformed not open bracket"},
		{":deleg: 153", nil, "non existing signature algorithm type: 153"},
		{":cert: 153", nil, "non existing certificate protocol type"},
		{":srv: name NaN", nil, "strconv.Atoi: parsing \"NaN\": invalid syntax"},
		{":infra: 153", nil, "non existing signature algorithm type: 153"},
		{":extra: rains 153", nil, "non existing signature algorithm type: 153"},
		{":next: 153", nil, "non existing signature algorithm type: 153"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		objs, err := decodeObjects(scanner)
		for i, o := range objs {
			if o.CompareTo(test.want[i]) != 0 {
				t.Errorf("incorrect decoding of object. expected=%v, actual=%v", test.want[i], o)
			}
		}

		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeAssertion(t *testing.T) {
	assertions, assertionEncodings := getAssertionAndEncodings("")
	var tests = []struct {
		input        string
		want         *rainslib.AssertionSection
		wantErrorMsg string
	}{
		{assertionEncodings[2], assertions[2], ""},
		{"WrongType", nil, "ZoneFile malformed wrong section type"},
		{":A: ", nil, "ZoneFile malformed, missing open bracket"},
		{":A: ethz.ch [ ", nil, "ZoneFile malformed unsupported objectType"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		a, err := decodeAssertion("", "", scanner)
		if a != nil && a.CompareTo(test.want) != 0 {
			t.Errorf("incorrect decoding of assertion. expected=%v, actual=%v", test.want, a)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeShard(t *testing.T) {
	shards, shardEncodings := getShardAndEncodings()

	var tests = []struct {
		input        string
		want         []*rainslib.AssertionSection
		wantErrorMsg string
	}{
		{shardEncodings[3], shards[3].Content, ""},
		{"WrongType", nil, "ZoneFile malformed wrong section type"},
		{":S: ", nil, "ZoneFile malformed, missing open bracket"},
		{":S:  [ WrongType", nil, "ZoneFile malformed wrong section type"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		s, err := decodeShard("", "", scanner)
		for i, a := range s {
			if a != nil && a.CompareTo(test.want[i]) != 0 {
				t.Errorf("incorrect decoding of shard. expected=%v, actual=%v", test.want[i], a)
			}
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeZone(t *testing.T) {
	zones, zoneEncodings := getZonesAndEncodings()

	var tests = []struct {
		input        string
		want         []*rainslib.AssertionSection
		wantErrorMsg string
	}{
		{zoneEncodings[0], []*rainslib.AssertionSection{zones[0].Content[0].(*rainslib.AssertionSection), zones[0].Content[1].(*rainslib.ShardSection).Content[0]}, ""},
		{"WrongType", nil, "ZoneFile malformed wrong section type"},
		{":Z: ch . ", nil, "ZoneFile malformed, missing open bracket"},
		{":Z: ch . [ WrongType", nil, "ZoneFile malformed wrong section type"},
		{":Z: ch . [ :A: ", nil, "ZoneFile malformed, missing open bracket"},
		{":Z: ch . [ :S: ", nil, "ZoneFile malformed, missing open bracket"},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
		z, err := decodeZone(scanner)
		for i, a := range z {
			//contained section must not have a context or subjectZone, thus to compare it, inherit the value from the zone
			test.want[i].Context = zones[0].Context
			test.want[i].SubjectZone = zones[0].SubjectZone
			if a != nil && a.CompareTo(test.want[i]) != 0 {
				t.Errorf("incorrect decoding of zone. expected=%v, actual=%v", test.want[i], a)
			}
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("Wrong error message. expected=%s, actual=%s", test.wantErrorMsg, err.Error())
		}
	}
}
