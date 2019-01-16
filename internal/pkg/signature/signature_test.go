package signature

import (
	"math/rand"
	"reflect"
	"sort"
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

func TestSigCompareTo(t *testing.T) {
	sigs := sortedSigs()
	shuffled := append([]Sig{}, sigs...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].CompareTo(shuffled[j]) < 0
	})
	for i, s := range sigs {
		if !reflect.DeepEqual(s, shuffled[i]) {
			t.Fatalf("compareTo did not work correctly: sorted=%v result=%v", sigs, shuffled)
		}
	}
}

func sortedSigs() []Sig {
	sigs := []Sig{}
	for i := 0; i < 1; i++ {
		for j := 0; j < 2; j++ {
			for k := 0; k < 2; k++ {
				for l := 0; l < 2; l++ {
					for m := 0; m < 2; m++ {
						for n := 0; n < 2; n++ {
							sigs = append(sigs, Sig{
								PublicKeyID: keys.PublicKeyID{
									Algorithm: algorithmTypes.Signature(i + 1),
									KeySpace:  keys.KeySpaceID(j),
									KeyPhase:  k,
								},
								ValidSince: int64(l),
								ValidUntil: int64(m),
								Data:       make([]byte, 1+n),
							})
						}
					}
				}
			}
		}
	}
	sigs = append(sigs, sigs[len(sigs)-1]) //equals
	return sigs
}
