package rainslib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestMessageSectionWithSigSignatures(t *testing.T) {
	sig1 := Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("testData")}
	sig2 := Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 3000, ValidUntil: 4500, Data: []byte("testData2")}
	var tests = []struct {
		input MessageSectionWithSig
	}{
		{new(AssertionSection)},
		{new(ShardSection)},
		{new(ZoneSection)},
		{new(AddressAssertionSection)},
		{new(AddressZoneSection)},
	}
	for i, test := range tests {
		test.input.AddSig(sig1)
		if len(test.input.Sigs()) != 1 {
			t.Errorf("%d: Added signature does not match stored count. expected=%v, actual=%v", i, sig1, test.input.Sigs()[0])
		}
		CheckSignatures(test.input.Sigs(), []Signature{sig1}, t)
		test.input.AddSig(sig2)
		if len(test.input.Sigs()) != 2 {
			t.Errorf("%d: Added signature does not match stored count. expected=%v, actual=%v", i, sig2, test.input.Sigs()[0])
		}
		CheckSignatures(test.input.Sigs(), []Signature{sig1, sig2}, t)
		test.input.DeleteSig(1)
		if len(test.input.Sigs()) != 1 {
			t.Errorf("%d: Not the specified signature was deleted. expectedToStay=%v, actualStayed=%v", i, sig1, test.input.Sigs()[0])
		}
		CheckSignatures(test.input.Sigs(), []Signature{sig1}, t)
		test.input.DeleteSig(0)
		if len(test.input.Sigs()) != 0 {
			t.Errorf("%d: Added signature does not match stored one. expected=%v, actual=%v", i, sig1, test.input.Sigs()[0])
		}
	}
}

func TestMessageSectionWithSigGetContextAndSubjectZone(t *testing.T) {
	var tests = []struct {
		input MessageSectionWithSig
	}{
		{&AssertionSection{Context: "testContextcx-testSubjectZone", SubjectZone: "testSubjectZone"}},
		{&ShardSection{Context: "testContextcx-testSubjectZone", SubjectZone: "testSubjectZone"}},
		{&ZoneSection{Context: "testContextcx-testSubjectZone", SubjectZone: "testSubjectZone"}},
		{&AddressAssertionSection{Context: "testContextcx-testSubjectZone"}},
		{&AddressZoneSection{Context: "testContextcx-testSubjectZone"}},
	}
	for i, test := range tests {
		if test.input.GetContext() != "testContextcx-testSubjectZone" {
			t.Errorf("%d: Context does not match. expected=testContextcx-testSubjectZone actual=%s", i, test.input.GetContext())
		}
		if test.input.GetSubjectZone() != "testSubjectZone" {
			t.Errorf("%d: SubjectZone does not match. expected=testSubjectZone actual=%s", i, test.input.GetSubjectZone())
		}
	}
}

func TestTokenString(t *testing.T) {
	tok := []byte("0123456789abcdsf")
	token := Token{}
	copy(token[:], tok)
	if token.String() != "30313233343536373839616263647366" {
		t.Errorf("Wrong String representation. expected=%s, actual=%s", "30313233343536373839616263647366", token.String())
	}
}

func TestInterval(t *testing.T) {
	total := TotalInterval{}
	if total.Begin() != "" || total.End() != "" {
		t.Errorf("The total interval's Begin and End should result in empty strings. Begin=%s, End=%s", total.Begin(), total.End())
	}
	stringInterval := StringInterval{Name: "TestName"}
	if stringInterval.Begin() != stringInterval.End() {
		t.Errorf("The string interval's Begin and End method must result in the same value. Begin=%s, End=%s", stringInterval.Begin(), stringInterval.End())
	}
}

func TestGetSignatureMetaData(t *testing.T) {
	var tests = []struct {
		input Signature
		want  string
	}{
		{Signature{}, "0 0 0 0"},
		{Signature{Algorithm: Ed448}, "0 2 0 0"},
		{Signature{Algorithm: Ecdsa256}, "0 3 0 0"},
		{Signature{Algorithm: Ecdsa384}, "0 4 0 0"},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2, Data: []byte("testData")}, "0 1 1 2"},
	}
	for i, test := range tests {
		if test.input.GetSignatureMetaData() != test.want {
			t.Errorf("%d: Wrong Signature meta data. expected=%v, actual=%v", i, test.want, test.input.GetSignatureMetaData())
		}
	}
}

func TestSignatureString(t *testing.T) {
	var tests = []struct {
		input Signature
		want  string
	}{
		{Signature{}, "{KS=0 AT=0 VS=0 VU=0 data=notYetImplementedInStringMethod}"},
		{Signature{Algorithm: Ed448}, "{KS=0 AT=2 VS=0 VU=0 data=notYetImplementedInStringMethod}"},
		{Signature{Algorithm: Ecdsa256}, "{KS=0 AT=3 VS=0 VU=0 data=notYetImplementedInStringMethod}"},
		{Signature{Algorithm: Ecdsa384}, "{KS=0 AT=4 VS=0 VU=0 data=notYetImplementedInStringMethod}"},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2, Data: []byte("testData")}, "{KS=0 AT=1 VS=1 VU=2 data=7465737444617461}"},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2}, "{KS=0 AT=1 VS=1 VU=2 data=nil}"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong Signature meta data. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	ed25519PublicKey, ed25519PrivateKey, _ := ed25519.GenerateKey(nil)
	ed25519PublicKey2, ed25519PrivateKey2, _ := ed25519.GenerateKey(nil)
	curve256 := elliptic.P256()
	ecdsaPrivateKey, _ := ecdsa.GenerateKey(curve256, rand.Reader)
	ecdsaPrivateKey2, _ := ecdsa.GenerateKey(curve256, rand.Reader)
	var tests = []struct {
		input               Signature
		inputSignEncoding   string
		privateKey          interface{}
		publicKey           interface{}
		inputVerifyEncoding string
		want                bool
	}{
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey,
			ed25519PublicKey, "SomeEncoding", true},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa256, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "Some encoding", true},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "This is a test", true},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2}, "", ecdsaPrivateKey, ecdsaPrivateKey.Public(), "", true},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey,
			ed25519PublicKey, "DifferentEncoding", false}, //encoding not matching
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa256, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //encoding not matching
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //encoding not matching
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey2,
			ed25519PublicKey, "SomeEncoding", false}, //public and private keys do not match
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey,
			ed25519PublicKey2, "SomeEncoding", false}, //public and private keys do not match
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa256, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey2,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //public and private keys do not match
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa256, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey,
			ecdsaPrivateKey2.Public(), "DifferentEncoding", false}, //public and private keys do not match
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey2,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //public and private keys do not match
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey,
			ecdsaPrivateKey2.Public(), "DifferentEncoding", false}, //public and private keys do not match
	}
	for i, test := range tests {
		if test.input.SignData(test.privateKey, test.inputSignEncoding) != nil {
			t.Errorf("%d: Was not able to sign data. encoding=%s privateKey=%v publicKey=%v", i, test.inputSignEncoding, test.privateKey, test.publicKey)
		}
		if test.input.VerifySignature(test.publicKey, test.inputVerifyEncoding) != test.want {
			t.Errorf("%d: Signature verification failed. encoding=%s privateKey=%v publicKey=%v", i, test.inputVerifyEncoding, test.privateKey, test.publicKey)
		}
	}
}

func TestSignDataErrors(t *testing.T) {
	var tests = []struct {
		input         Signature
		inputEncoding string
		privateKey    interface{}
		errMsg        string
	}{
		{Signature{}, "SomeEncoding", nil, "privateKey is nil"}, //private key nil
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "could not assert type ed25519.PrivateKey"},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed448, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "ed448 not yet supported in SignData()"},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa256, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "could not assert type ecdsa.PrivateKey"},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "could not assert type ecdsa.PrivateKey"},
		{Signature{KeySpace: RainsKeySpace, Algorithm: SignatureAlgorithmType(-1), ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "signature algorithm type not supported"},
	}
	for i, test := range tests {
		err := test.input.SignData(test.privateKey, test.inputEncoding)
		if err == nil {
			t.Errorf("%d: No error occurred. encoding=%s privateKey=%v ", i, test.inputEncoding, test.privateKey)
		} else if err.Error() != test.errMsg {
			t.Errorf("%d: Error message wrong expected=%s actual=%s", i, test.errMsg, err.Error())
		}
	}
}

func TestVerifySignatureErrors(t *testing.T) {
	curve256 := elliptic.P256()
	ecdsaPrivateKey, _ := ecdsa.GenerateKey(curve256, rand.Reader)
	var tests = []struct {
		input         Signature
		inputEncoding string
		publicKey     interface{}
	}{
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", nil},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", nil},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ed448, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa256, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{KeySpace: RainsKeySpace, Algorithm: SignatureAlgorithmType(-1), ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa256, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", ecdsaPrivateKey.Public()},
		{Signature{KeySpace: RainsKeySpace, Algorithm: Ecdsa384, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", ecdsaPrivateKey.Public()},
	}
	for i, test := range tests {
		if test.input.VerifySignature(test.publicKey, test.inputEncoding) {
			t.Errorf("%d: Signature verification did not fail. signature=%v encoding=%s publicKey=%v", i, test.input, test.inputEncoding, test.publicKey)
		}
	}
}

func TestConnInfoString(t *testing.T) {
	tcpAddrIP4, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:80")
	tcpAddrIP6, _ := net.ResolveTCPAddr("tcp", "[2001:db8::68]:80")
	var tests = []struct {
		input ConnInfo
		want  string
	}{
		{ConnInfo{}, ""},
		{ConnInfo{Type: NetworkAddrType(-1)}, ""},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, "127.0.0.1:80"},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, "[2001:db8::68]:80"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong Signature meta data. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestConnInfoHash(t *testing.T) {
	tcpAddrIP4, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:80")
	tcpAddrIP6, _ := net.ResolveTCPAddr("tcp", "[2001:db8::68]:80")
	var tests = []struct {
		input ConnInfo
		want  string
	}{
		{ConnInfo{}, "0_"},
		{ConnInfo{Type: NetworkAddrType(-1)}, "-1_"},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, "1_127.0.0.1:80"},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, "1_[2001:db8::68]:80"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong Signature Hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestConnInfoEqual(t *testing.T) {
	tcpAddrIP4, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:80")
	tcpAddrIP4_2, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:90")
	tcpAddrIP4_3, _ := net.ResolveTCPAddr("tcp", "127.0.0.2:80")
	tcpAddrIP6, _ := net.ResolveTCPAddr("tcp", "[2001:db8::68]:80")
	tcpAddrIP6_2, _ := net.ResolveTCPAddr("tcp", "[2001:db8::68]:100")
	tcpAddrIP6_3, _ := net.ResolveTCPAddr("tcp", "[2001:db8::78]:80")
	var tests = []struct {
		input      ConnInfo
		inputParam ConnInfo
		want       bool
	}{
		{ConnInfo{}, ConnInfo{}, false},                                   //noType
		{ConnInfo{Type: NetworkAddrType(-1)}, ConnInfo{Type: TCP}, false}, //no existing type
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, true},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, true},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, false},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, false},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4_2}, false},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4_3}, false},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6_2}, false},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6_3}, false},
	}
	for i, test := range tests {
		if test.input.Equal(test.inputParam) != test.want {
			t.Errorf("%d: Wrong Signature meta data. expected=%v, actual=%v", i, test.want, test.input.Equal(test.inputParam))
		}
	}
}

func TestSort(t *testing.T) {
	var tests = []struct {
		input  []MessageSection
		sorted []MessageSection
	}{
		{[]MessageSection{&NotificationSection{}, &QuerySection{}, &ZoneSection{}, &ShardSection{}, &AssertionSection{}, &AddressAssertionSection{},
			&AddressZoneSection{}, &AddressQuerySection{}},
			[]MessageSection{&AddressQuerySection{}, &AddressZoneSection{}, &AddressAssertionSection{}, &AssertionSection{}, &ShardSection{},
				&ZoneSection{}, &QuerySection{}, &NotificationSection{}}},
		//TODO add test for each separate. meaning comparing shard with shard, then zone with zone etc.
	}
	for i, test := range tests {
		m := &RainsMessage{Content: test.input}
		m.Sort()
		if !reflect.DeepEqual(m.Content, test.sorted) {
			t.Errorf("%d: RainsMessage.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, m.Content)
		}
	}
}
