package rainslib

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

func TestNameObjectCompareTo(t *testing.T) {
	nos := sortedNameObjects(9)
	var shuffled []NameObject
	for _, no := range nos {
		shuffled = append(shuffled, no)
	}
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].CompareTo(shuffled[j]) < 0 })
	for i, no := range nos {
		if !reflect.DeepEqual(no, shuffled[i]) {
			t.Errorf("%d: name objects are in wrong order expected=%v actual%v", i, no, shuffled[i])
		}
	}
}

func TestSignatureAlgorithmTypeString(t *testing.T) {
	var tests = []struct {
		input SignatureAlgorithmType
		want  string
	}{
		{SignatureAlgorithmType(0), "0"},
		{Ed25519, "1"},
		{Ed448, "2"},
		{Ecdsa256, "3"},
		{Ecdsa384, "4"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong Signature algorithm String value. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestPublicKeyCompareTo(t *testing.T) {
	pks := sortedPublicKeys(9)
	var shuffled []PublicKey
	for _, pk := range pks {
		shuffled = append(shuffled, pk)
	}
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].CompareTo(shuffled[j]) < 0 })
	for i, pk := range pks {
		if !reflect.DeepEqual(pk, shuffled[i]) {
			t.Errorf("%d: name objects are in wrong order expected=%v actual%v", i, pk, shuffled[i])
		}
	}
	pk1 := pks[0]
	pk1.Key = []byte{}
	if pk1.CompareTo(pks[0]) != 0 {
		t.Error("Error case was not hit")
	}
	if pks[0].CompareTo(pk1) != 0 {
		t.Error("Error case was not hit")
	}
	//TODO CFE remove teh next 2 test cases when we have more than one keyspace.
	pk1.KeySpace = KeySpaceID(1)
	if pk1.CompareTo(pks[0]) != 1 {
		t.Error("key space comparison")
	}
	pk1.KeySpace = KeySpaceID(-1)
	if pk1.CompareTo(pks[0]) != -1 {
		t.Error("key space comparison")
	}
}

func TestCertificateCompareTo(t *testing.T) {
	certs := sortedCertificates(9)
	var shuffled []CertificateObject
	for _, cert := range certs {
		shuffled = append(shuffled, cert)
	}
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].CompareTo(shuffled[j]) < 0 })
	for i, cert := range certs {
		if !reflect.DeepEqual(cert, shuffled[i]) {
			t.Errorf("%d: name objects are in wrong order expected=%v actual%v", i, cert, shuffled[i])
		}
	}
}

func TestServiceInfoCompareTo(t *testing.T) {
	sis := sortedServiceInfo(5)
	var shuffled []ServiceInfo
	for _, si := range sis {
		shuffled = append(shuffled, si)
	}
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].CompareTo(shuffled[j]) < 0 })
	for i, si := range sis {
		if !reflect.DeepEqual(si, shuffled[i]) {
			t.Errorf("%d: name objects are in wrong order expected=%v actual%v", i, si, shuffled[i])
		}
	}
}
