package signature

import (
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

func TestSignDataErrors(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		sig      *Sig
		key      interface{}
		expected string
	}{
		{&Sig{}, nil, "privateKey is nil"},
		{&Sig{}, key, "signature algorithm type not supported: Signature(0)"},
		{&Sig{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}},
			Sig{}, "could not assert type ed25519.PrivateKey"},
	}
	for i, test := range tests {
		err := test.sig.SignData(test.key, []byte("Wrong encoding"))
		if err == nil || err.Error() != test.expected {
			t.Fatalf("%d: Unexpected error result, expected=%s actual=%s", i, test.expected, err.Error())
		}
	}
}

func TestVerifySignatureErrors(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		sig *Sig
		key interface{}
	}{
		{&Sig{}, nil},
		{&Sig{Data: []byte("some data")}, nil},
		{&Sig{Data: []byte("some data")}, key},
		{&Sig{Data: "sd", PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}}, Sig{}},
	}
	for i, test := range tests {
		ok := test.sig.VerifySignature(test.key, []byte("Wrong encoding"))
		if ok {
			t.Fatalf("%d: Signature should not verify", i)
		}
	}
}
