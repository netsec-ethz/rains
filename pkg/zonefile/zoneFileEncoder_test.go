package zonefile

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
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

func TestEncodeNameObject(t *testing.T) {
	var tests = []struct {
		input object.Name
		want  string
	}{
		{object.Name{
			Name: "name.ethz.ch",
			Types: []object.Type{
				object.OTName,
				object.OTIP6Addr,
				object.OTIP4Addr,
				object.OTRedirection,
				object.OTDelegation,
				object.OTNameset,
				object.OTCertInfo,
				object.OTServiceInfo,
				object.OTRegistrar,
				object.OTRegistrant,
				object.OTInfraKey,
				object.OTExtraKey,
				object.OTNextKey,
				object.OTScionAddr6,
				object.OTScionAddr4,
			},
		}, "name.ethz.ch [ :name: :ip6: :ip4: :redir: :deleg: :nameset: :cert: :srv: :regr: :regt: :infra: :extra: :next: :scionip6: :scionip4: ]"},
		{object.Name{Name: "ethz.ch", Types: []object.Type{object.Type(-1)}}, "ethz.ch [  ]"},
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
		input keys.PublicKey
		want  string
	}{
		{keys.PublicKey{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}, Key: pkey}, fmt.Sprintf(":ed25519: 0 %s", hex.EncodeToString(pkey))},
		{keys.PublicKey{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}, Key: []byte(" ")}, ""},
		{keys.PublicKey{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed448}}, ""},
		{keys.PublicKey{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Signature(-1)}}, ""},
	}
	for _, test := range tests {
		if encodeEd25519PublicKey(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeEd25519PublicKey(test.input))
		}
	}
}

func TestEncodeKeySpace(t *testing.T) {
	var tests = []struct {
		input keys.KeySpaceID
		want  string
	}{
		{keys.RainsKeySpace, ":rains:"},
		{keys.KeySpaceID(-1), ""},
	}
	for _, test := range tests {
		if encodeKeySpace(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeKeySpace(test.input))
		}
	}
}

func TestEncodeCertificateErrors(t *testing.T) {
	var tests = []struct {
		input object.Certificate
		want  string
	}{
		{object.Certificate{Type: object.ProtocolType(-1)}, ""},
		{object.Certificate{Type: object.PTTLS, Usage: object.CertificateUsage(-1)}, ""},
		{object.Certificate{Type: object.PTTLS, Usage: object.CUTrustAnchor, HashAlgo: algorithmTypes.Hash(-1)}, ""},
	}
	for _, test := range tests {
		if encodeCertificate(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeCertificate(test.input))
		}
	}
}

func TestEncodeObjectErrors(t *testing.T) {
	var tests = []struct {
		input []object.Object
		want  string
	}{
		{[]object.Object{object.Object{Type: object.OTName}}, ""},
		{[]object.Object{object.Object{Type: object.OTDelegation}}, ""},
		{[]object.Object{object.Object{Type: object.OTCertInfo}}, ""},
		{[]object.Object{object.Object{Type: object.OTServiceInfo}}, ""},
		{[]object.Object{object.Object{Type: object.OTInfraKey}}, ""},
		{[]object.Object{object.Object{Type: object.OTExtraKey}}, ""},
		{[]object.Object{object.Object{Type: object.OTNextKey}}, ""},
		{[]object.Object{object.Object{Type: object.OTNextKey}}, ""},
		{[]object.Object{object.Object{Type: object.Type(-1)}}, ""},
	}
	for _, test := range tests {
		if encodeObjects(test.input, "") != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, encodeObjects(test.input, ""))
		}
	}
}
