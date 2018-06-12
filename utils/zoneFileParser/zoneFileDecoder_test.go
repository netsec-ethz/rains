package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/netsec-ethz/rains/rainslib"

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
			"wrong public key length: got 11, want: 32",
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
	for i, test := range tests {
		pkey, err := decodeEd25519PublicKeyData(test.input, test.inputKey)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("case %d: Resulting publicKey incorrect after decoding. expected=%v, actual=%v", i, test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
	for i, test := range tests {
		keyAlgo, err := decodeKeyAlgoType(test.input)
		if keyAlgo != test.want {
			t.Errorf("case %d: incorrect decoding of keyAlgoType. expected=%v, actual=%v", i, test.want, keyAlgo)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
			rainslib.PublicKey{}, "wrong public key length: got 11, want: 32"},
		{"ed448", rainslib.PublicKey{}, "ed448 not yet implemented"},
		{"ecdsa256", rainslib.PublicKey{}, "ecdsa256 not yet implemented"},
		{"ecdsa384", rainslib.PublicKey{}, "ecdsa384 not yet implemented"},
		{"noEncoding", rainslib.PublicKey{}, "non existing signature algorithm type: noEncoding"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		pkey, err := decodeSigAlgoAndData(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of publicKey. expected=%v, actual=%v", i, test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", rainslib.PublicKey{}, "expected :next: but got WrongType at line 1"},
		{":next: inexistentAlgoType", rainslib.PublicKey{}, "non existing signature algorithm type: inexistentAlgoType"},
		{fmt.Sprintf(":next: ed25519 %s NaN1 10", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))), rainslib.PublicKey{}, "expected number for ValidSince but got NaN1 at line 1 : strconv.ParseInt: parsing \"NaN1\": invalid syntax"},
		{fmt.Sprintf(":next: ed25519 %s 5 NaN2", hex.EncodeToString([]byte("KeyDataOfLength32 90123456789012"))), rainslib.PublicKey{}, "expected number for ValidUntil but got NaN2 at line 1 : strconv.ParseInt: parsing \"NaN2\": invalid syntax"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		pkey, err := decodeNextKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of nextKey. expected=%v, actual=%v", i, test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", rainslib.PublicKey{}, "expected :extra: but got: WrongType at line 1"},
		{":extra: UnsupportedKeySpaceID", rainslib.PublicKey{}, "expected known key type but got: UnsupportedKeySpaceID at line 1"},
		{":extra: rains inexistentAlgoType", rainslib.PublicKey{}, "non existing signature algorithm type: inexistentAlgoType"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		pkey, err := decodeExternalKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of extraKey. expected=%v, actual=%v", i, test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", rainslib.PublicKey{}, "expected ':infra:' but got WrongType at line 1"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		pkey, err := decodeInfraKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of infraKey. expected=%v, actual=%v", i, test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", rainslib.PublicKey{}, "expected ':deleg:' but got WrongType at line 1"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		pkey, err := decodeDelegationKey(scanner)
		if pkey.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of delegKey. expected=%v, actual=%v", i, test.want, pkey)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"FalseEncoding", rainslib.HashAlgorithmType(-1), "non existing certificate hash algorithm type: FalseEncoding"},
	}
	for i, test := range tests {
		hashAlgo, err := decodeCertHashType(test.input)
		if hashAlgo != test.want {
			t.Errorf("case %d: incorrect decoding of certHashType. expected=%v, actual=%v", i, test.want, hashAlgo)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"FalseEncoding", rainslib.CertificateUsage(-1), "non existing certificate usage type: FalseEncoding"},
	}
	for i, test := range tests {
		certUsage, err := decodeCertUsage(test.input)
		if certUsage != test.want {
			t.Errorf("case %d: incorrect decoding of certUsageType. expected=%v, actual=%v", i, test.want, certUsage)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"FalseEncoding", rainslib.ProtocolType(-1), "non existing certificate protocol type: FalseEncoding"},
	}
	for i, test := range tests {
		certPT, err := decodeCertPT(test.input)
		if certPT != test.want {
			t.Errorf("case %d: incorrect decoding of certProtocolType. expected=%v, actual=%v", i, test.want, certPT)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", rainslib.CertificateObject{}, "expected ':cert:' but got WrongType at line 1"},
		{":cert: wrongPT", rainslib.CertificateObject{}, "non existing certificate protocol type: wrongPT"},
		{":cert: tls wrongCU", rainslib.CertificateObject{}, "non existing certificate usage type: wrongCU"},
		{":cert: tls trustAnchor wrongAlgo", rainslib.CertificateObject{}, "non existing certificate hash algorithm type: wrongAlgo"},
		{":cert: tls trustAnchor sha256 noHexEncoding", rainslib.CertificateObject{}, "encoding/hex: invalid byte: U+006E 'n'"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		cert, err := decodeCertObject(scanner)
		if cert.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of delegKey. expected=%v, actual=%v", i, test.want, cert)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
		}
	}
}

func TestDecodeFreeText(t *testing.T) {
	var tests = []struct {
		input string
		want  string
		err   string
	}{
		{":regt: Hello my name is ]", "Hello my name is", ""},
		{":regt: Hello my name is :ip:", "Hello my name is", ""},
		{":redir: Hello my name is   ", "", "unexpected EOF while parsing free text"}, //not finished correctly, return empty string
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		text, err := decodeFreeText(scanner)
		if test.err == "" && err != nil {
			t.Errorf("case %d: expected nil err, but got %v", i, err)
		} else if err != nil && err.Error() != test.err {
			t.Errorf("case %d: exptected error %q but got %q", i, test.err, err.Error())
		}
		if text != test.want {
			t.Errorf("case %d: incorrect decoding of delegKey. expected=%v, actual=%v", i, test.want, text)
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
		{"WrongType", rainslib.ServiceInfo{}, "failed parsing serviceInfo, expected :SRV: but got WrongType at line 1"},
		{":srv: ethz.ch NaN1", rainslib.ServiceInfo{}, "expected number but got NaN1 at line 1 : strconv.Atoi: parsing \"NaN1\": invalid syntax"},
		{":srv: ethz.ch 80 NaN2", rainslib.ServiceInfo{}, "expected number but got NaN2 at line 1 : strconv.Atoi: parsing \"NaN2\": invalid syntax"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		srvInfo, err := decodeServiceInfo(scanner)
		if srvInfo.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of serviceInfo object. expected=%v, actual=%v", i, test.want, srvInfo)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", rainslib.NameObject{}, "expected ':name:' but got WrongType at line 1"},
		{":name: ethz.ch NotOpenBracket", rainslib.NameObject{}, "malformed input: expected '[' but got NotOpenBracket at line 1"},
		{":name: ethz.ch [ NotAnObjectType", rainslib.NameObject{}, "malformed object type: NotAnObjectType at line 1"},
		{":name: ethz.ch [ cert ", rainslib.NameObject{}, "malformed input: expected ']' but got  at line 2"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		nameObject, err := decodeNameObject(scanner)
		if nameObject.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of nameObject. expected=%v, actual=%v", i, test.want, nameObject)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", nil, "malformed input: expected :<objectType>: (e.g. :ip4:) actual: WrongType at line 1"},
		{":ip4: 127.0.0.1 ", nil, "malformed input: expected ']' but got  at line 2"},
		{":name: name NotABracket", nil, "malformed input: expected '[' but got NotABracket at line 1"},
		{":deleg: 153", nil, "non existing signature algorithm type: 153"},
		{":cert: 153", nil, "non existing certificate protocol type: 153"},
		{":srv: name NaN", nil, "expected number but got NaN at line 1 : strconv.Atoi: parsing \"NaN\": invalid syntax"},
		{":infra: 153", nil, "non existing signature algorithm type: 153"},
		{":extra: rains 153", nil, "non existing signature algorithm type: 153"},
		{":next: 153", nil, "non existing signature algorithm type: 153"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		objs, err := decodeObjects(scanner)
		for j, o := range objs {
			if o.CompareTo(test.want[j]) != 0 {
				t.Errorf("case %d: incorrect decoding of object. expected=%v, actual=%v", i, test.want[j], o)
			}
		}

		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", nil, "error decoding assertion: expected ':A:' but got WrongType at line 1"},
		{":A: ", nil, "error decoding assertion: expected '[' but got  at line 2"},
		{":A: ethz.ch [ ", nil, "malformed input: expected :<objectType>: (e.g. :ip4:) actual:  at line 2"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		a, err := decodeAssertion("", "", scanner)
		if a != nil && a.CompareTo(test.want) != 0 {
			t.Errorf("case %d: incorrect decoding of assertion. expected=%v, actual=%v", i, test.want, a)
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", nil, "expected shard ':S:' but got WrongType at line 1"},
		{":S: ", nil, "expected '[' but got  at line 2"},
		{":S:  [ WrongType", nil, "error decoding assertion: expected ':A:' but got WrongType at line 1"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		scanner.Scan()
		s, err := decodeShard("", "", scanner)
		for j, a := range s {
			if a != nil && a.CompareTo(test.want[j]) != 0 {
				t.Errorf("case %d: incorrect decoding of shard. expected=%v, actual=%v", i, test.want[j], a)
			}
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
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
		{"WrongType", nil, "malformed zonefile: expected ':Z:' got: WrongType at line 1"},
		{":Z: ch . ", nil, "malformed zonefile: expected '[' got:  at line 2"},
		{":Z: ch . [ WrongType", nil, "malformed zonefile: expected ':A:' or ':S:' but got WrongType at line 1"},
		{":Z: ch . [ :A: ", nil, "error decoding assertion: expected '[' but got  at line 2"},
		{":Z: ch . [ :S: ", nil, "expected '[' but got  at line 2"},
	}
	for i, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		z, err := decodeZone(scanner)
		for j, a := range z {
			// contained section must not have a context or subjectZone, thus
			// to compare it, inherit the value from the zone.
			test.want[j].Context = zones[0].Context
			test.want[j].SubjectZone = zones[0].SubjectZone
			if a != nil && a.CompareTo(test.want[j]) != 0 {
				t.Errorf("case %d: incorrect decoding of zone. expected=%v, actual=%v", i, test.want[j], a)
			}
		}
		if err != nil && err.Error() != test.wantErrorMsg {
			t.Errorf("case %d: Wrong error message. expected=%s, actual=%s", i, test.wantErrorMsg, err.Error())
		}
	}
}
