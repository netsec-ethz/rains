package keyManager

import (
	"encoding/pem"
	"fmt"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	GenerateKey("testdata", "test", "description3", "ed25519", "testPwd", 1)
	if LoadPublicKeys("testdata") == "" {
		t.Fatal("was not able to load public keys")
	}
	if DecryptKey("testdata", "test_pub.pem", "testPwd") != nil {
		t.Fatal("was not able to decrypt private keys")
	}
}

func TestLoadPublicKeys(t *testing.T) {
	var tests = []struct {
		path   string
		result string
	}{
		{"testdata/publicKeyTest", `-----BEGIN RAINS PUBLIC KEY-----
description: description2
keyAlgo: ed25519
keyPhase: 1

FX4mSFylma5gJKxyipQomDfcG35cykCmF/TVDldpTDo=
-----END RAINS PUBLIC KEY-----

-----BEGIN RAINS PUBLIC KEY-----
description: description
keyAlgo: ed25519
keyPhase: 1

8GjPXoeiLjI8IXtvNQhUJM59FFpZKPF3l+2YorfRWCU=
-----END RAINS PUBLIC KEY-----
`},
	}
	for i, test := range tests {
		if LoadPublicKeys(test.path) != test.result {
			t.Fatalf("%d: Was not able to load public keys, expected=%s actual=%s", i,
				test.result, LoadPublicKeys(test.path))
		}
	}
}

func TestDecryptKey(t *testing.T) {
	var tests = []struct {
		path   string
		name   string
		pwd    string
		result string
	}{
		{"testdata/privateKeyTest", "test", "testPwd", `-----BEGIN RAINS ENCRYPTED PRIVATE KEY-----
description: description
iv: 59540bd9d74515e2f33be1ee9cc80dea
keyAlgo: ed25519
keyPhase: 1
salt: d720625555f7b4ad

ROEfF6uzOsPP20+mADJFpvU6SmHrmUlrdvf62PprS7nwaM9eh6IuMjwhe281CFQk
zn0UWlko8XeX7Ziit9FYJQ==
-----END RAINS ENCRYPTED PRIVATE KEY-----
`},
		{"testdata/privateKeyTest", "test2", "testPwd", `-----BEGIN RAINS ENCRYPTED PRIVATE KEY-----
description: description2
iv: a8bcc983643b3cfbe3781694a43ad90a
keyAlgo: ed25519
keyPhase: 1
salt: 0f6d4d32946fe782

/i6JnB6qUwgcB+sYs/8cCbIMwCqvq+wBzXxLrZPi+gUVfiZIXKWZrmAkrHKKlCiY
N9wbflzKQKYX9NUOV2lMOg==
-----END RAINS ENCRYPTED PRIVATE KEY-----
`},
	}
	for i, test := range tests {
		if fmt.Sprintf("%s", pem.EncodeToMemory(DecryptKey(test.path, test.name, test.pwd))) != test.result {
			t.Fatalf("%d: Was not able to load public keys, expected=%s actual=%s", i,
				test.result,
				fmt.Sprintf("%s", pem.EncodeToMemory(DecryptKey(test.path, test.name, test.pwd))))
		}
	}
}
