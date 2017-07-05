package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"rains/rainslib"
	"testing"

	"golang.org/x/crypto/ed25519"
)

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
		{rainslib.NameObject{Name: "ethz.ch", Types: []rainslib.ObjectType{rainslib.ObjectType(-1)}}, "ethz.ch [  ]"},
	}
	for _, test := range tests {
		if encodeNameObject(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeNameObject(test.input))
		}
	}
}

func TestEncodePublicKey(t *testing.T) {
	pkey, _, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		input rainslib.PublicKey
		want  string
	}{
		{rainslib.PublicKey{Type: rainslib.Ed25519, Key: pkey}, fmt.Sprintf("ed25519 %s", hex.EncodeToString(pkey))},
		{rainslib.PublicKey{Type: rainslib.Ed25519, Key: []byte(" ")}, ""},
		{rainslib.PublicKey{Type: rainslib.Ed448}, ""},
		{rainslib.PublicKey{Type: rainslib.Ecdsa256}, ""},
		{rainslib.PublicKey{Type: rainslib.Ecdsa384}, ""},
		{rainslib.PublicKey{Type: rainslib.SignatureAlgorithmType(-1)}, ""},
	}
	for _, test := range tests {
		if encodePublicKey(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodePublicKey(test.input))
		}
	}
}

func TestEncodeKeySpace(t *testing.T) {
	var tests = []struct {
		input rainslib.KeySpaceID
		want  string
	}{
		{rainslib.RainsKeySpace, "rains"},
		{rainslib.KeySpaceID(-1), ""},
	}
	for _, test := range tests {
		if encodeKeySpace(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeKeySpace(test.input))
		}
	}
}

func TestEncodeCertificateErrors(t *testing.T) {
	var tests = []struct {
		input rainslib.CertificateObject
		want  string
	}{
		{rainslib.CertificateObject{Type: rainslib.ProtocolType(-1)}, ""},
		{rainslib.CertificateObject{Type: rainslib.PTTLS, Usage: rainslib.CertificateUsage(-1)}, ""},
		{rainslib.CertificateObject{Type: rainslib.PTTLS, Usage: rainslib.CUTrustAnchor, HashAlgo: rainslib.HashAlgorithmType(-1)}, ""},
	}
	for _, test := range tests {
		if encodeCertificate(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeCertificate(test.input))
		}
	}
}

func TestEncodeObjectErrors(t *testing.T) {
	var tests = []struct {
		input []rainslib.Object
		want  string
	}{
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTName}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTDelegation}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTCertInfo}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTServiceInfo}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTInfraKey}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTExtraKey}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTNextKey}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTNextKey}}, ""},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.ObjectType(-1)}}, ""},
	}
	for _, test := range tests {
		if encodeObjects(test.input, "") != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeObjects(test.input, ""))
		}
	}
}
