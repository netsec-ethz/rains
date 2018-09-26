package section

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
	sig1 := Signature{
		PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519},
		ValidSince:  1000,
		ValidUntil:  2000,
		Data:        []byte("testData"),
	}
	sig2 := Signature{
		PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519},
		ValidSince:  3000,
		ValidUntil:  4500,
		Data:        []byte("testData2"),
	}
	var tests = []struct {
		input SecWithSig
	}{
		{new(Assertion)},
		{new(Shard)},
		{new(Zone)},
		{new(AddrAssertion)},
		{new(AddressZoneSection)},
	}
	for i, test := range tests {
		test.input.AddSig(sig1)
		if len(test.input.AllSigs()) != 1 {
			t.Errorf("%d: Added signature does not match stored count. expected=%v, actual=%v", i, sig1, test.input.AllSigs()[0])
		}
		CheckSignatures(test.input.AllSigs(), []Signature{sig1}, t)
		test.input.AddSig(sig2)
		if len(test.input.AllSigs()) != 2 {
			t.Errorf("%d: Added signature does not match stored count. expected=%v, actual=%v", i, sig2, test.input.AllSigs()[0])
		}
		CheckSignatures(test.input.AllSigs(), []Signature{sig1, sig2}, t)
		test.input.DeleteSig(1)
		if len(test.input.AllSigs()) != 1 {
			t.Errorf("%d: Not the specified signature was deleted. expectedToStay=%v, actualStayed=%v", i, sig1, test.input.AllSigs()[0])
		}
		CheckSignatures(test.input.AllSigs(), []Signature{sig1}, t)
		test.input.DeleteSig(0)
		if len(test.input.AllSigs()) != 0 {
			t.Errorf("%d: Added signature does not match stored one. expected=%v, actual=%v", i, sig1, test.input.AllSigs()[0])
		}
	}
}

func TestMessageSectionWithSigGetContextAndSubjectZone(t *testing.T) {
	_, sampleNet, _ := net.ParseCIDR("2001:db8::/32")
	var tests = []struct {
		input             SecWithSig
		exptectCtx        string
		expectSubjectZone string
	}{
		{&Assertion{Context: "testContextcx-testSubjectZone", SubjectZone: "testSubjectZone"},
			"testContextcx-testSubjectZone", "testSubjectZone"},
		{&Shard{Context: "testContextcx-testSubjectZone", SubjectZone: "testSubjectZone"},
			"testContextcx-testSubjectZone", "testSubjectZone"},
		{&Zone{Context: "testContextcx-testSubjectZone", SubjectZone: "testSubjectZone"},
			"testContextcx-testSubjectZone", "testSubjectZone"},
		{&AddrAssertion{Context: "testContextcx-testSubjectZone", SubjectAddr: sampleNet},
			"testContextcx-testSubjectZone", "2001:db8::/32"},
		{&AddressZoneSection{Context: "testContextcx-testSubjectZone", SubjectAddr: sampleNet},
			"testContextcx-testSubjectZone", "2001:db8::/32"},
	}
	for i, test := range tests {
		if test.input.GetContext() != test.exptectCtx {
			t.Errorf("%d: Context does not match. expected=testContextcx-testSubjectZone actual=%s", i, test.input.GetContext())
		}
		if test.input.GetSubjectZone() != test.expectSubjectZone {
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

func TestSignatureMetaDataString(t *testing.T) {
	var tests = []struct {
		input SignatureMetaData
		want  string
	}{
		{SignatureMetaData{}, "0 0 0 0 0"},
		{SignatureMetaData{PublicKeyID: PublicKeyID{Algorithm: Ed448}}, "0 2 0 0 0"},
		{SignatureMetaData{PublicKeyID: PublicKeyID{Algorithm: Ecdsa256}}, "0 3 0 0 0"},
		{SignatureMetaData{PublicKeyID: PublicKeyID{Algorithm: Ecdsa384}}, "0 4 0 0 0"},
		{
			SignatureMetaData{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1,
				ValidUntil: 2,
			},
			"0 1 1 2 1"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong Signature meta data. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestGetSignatureMetaData(t *testing.T) {
	var tests = []struct {
		input Signature
		want  SignatureMetaData
	}{
		{Signature{}, SignatureMetaData{}},
		{
			Signature{PublicKeyID: PublicKeyID{Algorithm: Ed448}},
			SignatureMetaData{PublicKeyID: PublicKeyID{Algorithm: Ed448}},
		},
		{
			Signature{PublicKeyID: PublicKeyID{Algorithm: Ecdsa256}},
			SignatureMetaData{PublicKeyID: PublicKeyID{Algorithm: Ecdsa256}},
		},
		{
			Signature{PublicKeyID: PublicKeyID{Algorithm: Ecdsa384}},
			SignatureMetaData{PublicKeyID: PublicKeyID{Algorithm: Ecdsa384}},
		},
		{
			Signature{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1,
				ValidUntil: 2,
				Data:       []byte("testData"),
			},
			SignatureMetaData{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1,
				ValidUntil: 2,
			},
		},
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
		{Signature{}, "{KS=0 AT=0 VS=0 VU=0 KP=0 data=notYetImplementedInStringMethod}"},
		{Signature{PublicKeyID: PublicKeyID{Algorithm: Ed448}}, "{KS=0 AT=2 VS=0 VU=0 KP=0 data=notYetImplementedInStringMethod}"},
		{Signature{PublicKeyID: PublicKeyID{Algorithm: Ecdsa256}}, "{KS=0 AT=3 VS=0 VU=0 KP=0 data=notYetImplementedInStringMethod}"},
		{Signature{PublicKeyID: PublicKeyID{Algorithm: Ecdsa384}}, "{KS=0 AT=4 VS=0 VU=0 KP=0 data=notYetImplementedInStringMethod}"},
		{
			Signature{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  2,
				},
				ValidSince: 1,
				ValidUntil: 2,
				Data:       []byte("testData")},
			"{KS=0 AT=1 VS=1 VU=2 KP=2 data=7465737444617461}",
		},
		{
			Signature{
				PublicKeyID: PublicKeyID{
					KeySpace:  RainsKeySpace,
					Algorithm: Ed25519,
					KeyPhase:  1,
				},
				ValidSince: 1,
				ValidUntil: 2,
			},
			"{KS=0 AT=1 VS=1 VU=2 KP=1 data=nil}",
		},
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
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey,
			ed25519PublicKey, "SomeEncoding", true},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa256}, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "Some encoding", true},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "This is a test", true},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2}, "", ecdsaPrivateKey, ecdsaPrivateKey.Public(), "", true},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey,
			ed25519PublicKey, "DifferentEncoding", false}, //encoding not matching
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa256}, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //encoding not matching
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //encoding not matching
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey2,
			ed25519PublicKey, "SomeEncoding", false}, //public and private keys do not match
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", ed25519PrivateKey,
			ed25519PublicKey2, "SomeEncoding", false}, //public and private keys do not match
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa256}, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey2,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //public and private keys do not match
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa256}, ValidSince: 1, ValidUntil: 2}, "Some encoding", ecdsaPrivateKey,
			ecdsaPrivateKey2.Public(), "DifferentEncoding", false}, //public and private keys do not match
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey2,
			ecdsaPrivateKey.Public(), "DifferentEncoding", false}, //public and private keys do not match
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2}, "This is a test", ecdsaPrivateKey,
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
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "could not assert type ed25519.PrivateKey"},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed448}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "ed448 not yet supported in SignData()"},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa256}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "could not assert type ecdsa.PrivateKey"},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "could not assert type ecdsa.PrivateKey"},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: SignatureAlgorithmType(-1)}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", 5, "signature algorithm type not supported"},
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
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2}, "SomeEncoding", nil},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", nil},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed25519}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ed448}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa256}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: SignatureAlgorithmType(-1)}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", 5},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa256}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", ecdsaPrivateKey.Public()},
		{Signature{PublicKeyID: PublicKeyID{KeySpace: RainsKeySpace, Algorithm: Ecdsa384}, ValidSince: 1, ValidUntil: 2, Data: "notNil"}, "SomeEncoding", ecdsaPrivateKey.Public()},
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

func TestConnInfoNetworkAndAddr(t *testing.T) {
	tcpAddrIP4, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:80")
	tcpAddrIP6, _ := net.ResolveTCPAddr("tcp", "[2001:db8::68]:80")
	var tests = []struct {
		input ConnInfo
		want  string
	}{
		{ConnInfo{}, ""},
		{ConnInfo{Type: NetworkAddrType(-1)}, ""},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP4}, "tcp 127.0.0.1:80"},
		{ConnInfo{Type: TCP, TCPAddr: tcpAddrIP6}, "tcp [2001:db8::68]:80"},
	}
	for i, test := range tests {
		if test.input.NetworkAndAddr() != test.want {
			t.Errorf("%d: Wrong Signature meta data. expected=%v, actual=%v", i, test.want, test.input.NetworkAndAddr())
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
	_, subjectAddress, _ := net.ParseCIDR(ip4TestAddrCIDR24)
	var tests = []struct {
		input  []Section
		sorted []Section
	}{
		{
			[]Section{&Notification{}, &QueryForward{}, &Zone{}, &Shard{}, &Assertion{}, &AddrAssertion{}, //all sections
				&AddressZoneSection{}, &AddrQuery{}},
			[]Section{&AddrQuery{}, &AddressZoneSection{}, &AddrAssertion{}, &Assertion{}, &Shard{},
				&Zone{}, &QueryForward{}, &Notification{}},
		},

		{ //Assertion
			[]Section{
				&Assertion{
					Content: []Object{
						Object{Type: OTIP6Addr, Value: ip6TestAddr},
						Object{Type: OTIP4Addr, Value: ip4TestAddr},
					},
				},
				&Assertion{
					Content: []Object{
						Object{Type: OTIP4Addr, Value: "192.0.2.0"},
						Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTDelegation, OTName}}},
					},
				},
			},
			[]Section{
				&Assertion{
					Content: []Object{
						Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTName, OTDelegation}}},
						Object{Type: OTIP4Addr, Value: "192.0.2.0"},
					},
				},
				&Assertion{
					Content: []Object{
						Object{Type: OTIP6Addr, Value: ip6TestAddr},
						Object{Type: OTIP4Addr, Value: ip4TestAddr},
					},
				},
			},
		},

		{ //Shard
			[]Section{
				&Shard{
					Content: []*Assertion{
						&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
						&Assertion{Content: []Object{Object{Type: OTIP4Addr}, Object{Type: OTName}}},
					},
				},
				&Shard{
					Content: []*Assertion{
						&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTCertInfo}}},
						&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTName}}},
					},
				},
			},
			[]Section{
				&Shard{
					Content: []*Assertion{
						&Assertion{Content: []Object{Object{Type: OTName}, Object{Type: OTIP6Addr}}},
						&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTCertInfo}}},
					},
				},
				&Shard{
					Content: []*Assertion{
						&Assertion{Content: []Object{Object{Type: OTName}, Object{Type: OTIP4Addr}}},
						&Assertion{Content: []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}}},
					},
				},
			},
		},

		{ //Zone
			[]Section{
				&Zone{
					Content: []SecWithSigForward{&Shard{SubjectZone: "a"}, &Assertion{SubjectZone: "b"}},
				},
				&Zone{
					Content: []SecWithSigForward{&Shard{SubjectZone: "b"}, &Assertion{SubjectZone: "a"}},
				},
			},
			[]Section{
				&Zone{
					Content: []SecWithSigForward{&Assertion{SubjectZone: "a"}, &Shard{SubjectZone: "b"}},
				},
				&Zone{
					Content: []SecWithSigForward{&Assertion{SubjectZone: "b"}, &Shard{SubjectZone: "a"}},
				},
			},
		},

		{ //Query section
			[]Section{
				&QueryForward{Options: []QueryOption{QueryOption(5), QueryOption(3)}},
				&QueryForward{Options: []QueryOption{QueryOption(6), QueryOption(2)}},
			},
			[]Section{
				&QueryForward{Options: []QueryOption{QueryOption(2), QueryOption(6)}},
				&QueryForward{Options: []QueryOption{QueryOption(3), QueryOption(5)}},
			},
		},

		{ //AddressAssertion
			[]Section{
				&AddrAssertion{
					SubjectAddr: subjectAddress,
					Content: []Object{
						Object{Type: OTIP6Addr, Value: ip6TestAddr},
						Object{Type: OTIP4Addr, Value: ip4TestAddr},
					},
				},
				&AddrAssertion{
					SubjectAddr: subjectAddress,
					Content: []Object{
						Object{Type: OTIP4Addr, Value: ip4TestAddr},
						Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTDelegation, OTName}}},
					},
				},
			},
			[]Section{
				&AddrAssertion{
					SubjectAddr: subjectAddress,
					Content: []Object{
						Object{Type: OTName, Value: NameObject{Name: "name", Types: []ObjectType{OTName, OTDelegation}}},
						Object{Type: OTIP4Addr, Value: "192.0.2.0"},
					},
				},
				&AddrAssertion{
					SubjectAddr: subjectAddress,
					Content: []Object{
						Object{Type: OTIP6Addr, Value: ip6TestAddr},
						Object{Type: OTIP4Addr, Value: ip4TestAddr},
					},
				},
			},
		},

		{ //AddressZone
			[]Section{
				&AddressZoneSection{
					SubjectAddr: subjectAddress,
					Content: []*AddrAssertion{
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}},
						},
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTIP4Addr}, Object{Type: OTName}},
						},
					},
				},
				&AddressZoneSection{
					SubjectAddr: subjectAddress,
					Content: []*AddrAssertion{
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTIP6Addr}, Object{Type: OTName}},
						},
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTIP4Addr}, Object{Type: OTName}},
						},
					},
				},
			},
			[]Section{
				&AddressZoneSection{
					SubjectAddr: subjectAddress,
					Content: []*AddrAssertion{
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTName}, Object{Type: OTIP6Addr}},
						},
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTName}, Object{Type: OTIP4Addr}},
						},
					},
				},
				&AddressZoneSection{
					SubjectAddr: subjectAddress,
					Content: []*AddrAssertion{
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTName}, Object{Type: OTIP4Addr}},
						},
						&AddrAssertion{
							SubjectAddr: subjectAddress,
							Content:     []Object{Object{Type: OTIP6Addr}, Object{Type: OTDelegation}},
						},
					},
				},
			},
		},
		{ //AddressQueries
			[]Section{
				&AddrQuery{SubjectAddr: subjectAddress, Options: []QueryOption{QueryOption(5), QueryOption(3)}},
				&AddrQuery{SubjectAddr: subjectAddress, Options: []QueryOption{QueryOption(6), QueryOption(2)}},
			},
			[]Section{
				&AddrQuery{SubjectAddr: subjectAddress, Options: []QueryOption{QueryOption(2), QueryOption(6)}},
				&AddrQuery{SubjectAddr: subjectAddress, Options: []QueryOption{QueryOption(3), QueryOption(5)}},
			},
		},
		{ //Notifications
			[]Section{&Notification{Data: "2"}, &Notification{Data: "1"}},
			[]Section{&Notification{Data: "1"}, &Notification{Data: "2"}},
		},
	}
	for i, test := range tests {
		m := &RainsMessage{Content: test.input}
		m.Sort()
		if !reflect.DeepEqual(m.Content, test.sorted) {
			t.Errorf("%d: RainsMessage.Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, m.Content)
		}
	}
}

type MockInterval struct {
	begin string
	end   string
}

func (mi MockInterval) Begin() string {
	return mi.begin
}

func (mi MockInterval) End() string {
	return mi.end
}

func TestOverlapping(t *testing.T) {
	testMatrix := []struct {
		one    MockInterval
		two    MockInterval
		output bool
	}{
		{
			one:    MockInterval{"a", "z"},
			two:    MockInterval{"e", "n"},
			output: true,
		},
		{
			one:    MockInterval{"o", "w"},
			two:    MockInterval{"a", "e"},
			output: false,
		},
		{
			one:    MockInterval{"", "e"},
			two:    MockInterval{"n", "q"},
			output: false,
		},
		{
			one:    MockInterval{"a", ""},
			two:    MockInterval{"a", "z"},
			output: true,
		},
		{
			one:    MockInterval{"a", "p"},
			two:    MockInterval{"q", ""},
			output: false,
		},
		{
			one:    MockInterval{"a", "z"},
			two:    MockInterval{"", "b"},
			output: true,
		},
		{
			one:    MockInterval{"a", "a"},
			two:    MockInterval{"b", "b"},
			output: false,
		},
	}
	for i, entry := range testMatrix {
		if out := Intersect(entry.one, entry.two); out != entry.output {
			t.Errorf("case %d: wrong return type from Intersect: got %t, want %t", i, out, entry.output)
		}
	}
}
