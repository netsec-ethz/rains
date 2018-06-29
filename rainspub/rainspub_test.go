package rainspub

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/rainsd"
	"github.com/netsec-ethz/rains/rainslib"
	"golang.org/x/crypto/ed25519"
)

//TODO CFE Write Tests for rainspub

func TestLoadPrivateKeys(t *testing.T) {
	var expectedPrivateKey ed25519.PrivateKey
	expectedPrivateKey = make([]byte, hex.DecodedLen(len("80e1a328b908c2d6c2f10659355b15618ead2e42acf1dfcf39488fc7006c444e2245137bcb058f799843bb8c6df31927b547e4951142b99ae97c668b076e9d84")))
	hex.Decode(expectedPrivateKey, []byte("80e1a328b908c2d6c2f10659355b15618ead2e42acf1dfcf39488fc7006c444e2245137bcb058f799843bb8c6df31927b547e4951142b99ae97c668b076e9d84"))
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/zonePrivate.key", ""},
		{"notExist/zonePrivate.key", "open notExist/zonePrivate.key: no such file or directory"},
		{"test/malformed.conf", "encoding/hex: invalid byte: U+007B '{'"},
		{"test/zonePrivateWrongSize.key", "Private key length is incorrect"},
	}
	for i, test := range tests {
		zonePrivateKey, err := loadPrivateKey(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: loadPrivateKey() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && !reflect.DeepEqual(expectedPrivateKey, zonePrivateKey) {
			t.Errorf("%d: Loaded privateKey is not as expected. expected=%v, actual=%v", i, expectedPrivateKey, zonePrivateKey)
		}
	}
}

func TestSignZone(t *testing.T) {
	a := getAssertionWithTwoIPObjects()
	var tests = []struct {
		input   *rainslib.ZoneSection
		keyAlgo rainslib.SignatureAlgorithmType
		privKey interface{}
		errMsg  string
	}{
		{&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
			&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
				Content: []*rainslib.AssertionSection{a}}}}, rainslib.Ed25519, zonePrivateKey, ""},
		{nil, rainslib.Ed25519, nil, "zone is nil"},                                                      //zone is nil error
		{new(rainslib.ZoneSection), rainslib.Ed25519, nil, "Was not able to sign and add the signature"}, //signSection return error
		{&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
			new(rainslib.AssertionSection)}}, rainslib.Ed25519, zonePrivateKey,
			"Zone contained unexpected type expected=*ShardSection actual=*rainslib.AssertionSection"}, //invalid zone content error
	}
	for i, test := range tests {
		err := signZone(test.input, test.keyAlgo, test.privKey)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && (test.input.Signatures[0].Data == nil || test.input.Content[0].Sigs(rainslib.RainsKeySpace)[0].Data == nil ||
			test.input.Content[0].(*rainslib.ShardSection).Content[0].Signatures[0].Data == nil) {
			t.Errorf("%d: signZone() did not add signature to all sections.", i)
		}
	}
}

func TestSignShard(t *testing.T) {
	InitRainspub("test/rainspub.conf")
	a := getAssertionWithTwoIPObjects()
	var tests = []struct {
		input   *rainslib.ShardSection
		keyAlgo rainslib.SignatureAlgorithmType
		privKey interface{}
		errMsg  string
	}{
		{&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
			Content: []*rainslib.AssertionSection{a}}, rainslib.Ed25519, zonePrivateKey, ""},
		{nil, rainslib.Ed25519, nil, "shard is nil"},                                                      //shard is nil error
		{new(rainslib.ShardSection), rainslib.Ed25519, nil, "Was not able to sign and add the signature"}, //signSection return error
	}
	for i, test := range tests {
		err := signShard(test.input, test.keyAlgo, test.privKey)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && (test.input.Content[0].Sigs(rainslib.RainsKeySpace)[0].Data == nil ||
			test.input.Content[0].Signatures[0].Data == nil) {
			t.Errorf("%d: signZone() did not add signature to all sections.", i)
		}
	}
}

func TestSignAssertion(t *testing.T) {
	InitRainspub("test/rainspub.conf")
	a1 := getAssertionWithTwoIPObjects()
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := rainslib.PublicKey{PublicKeyID: rainslib.PublicKeyID{KeySpace: rainslib.RainsKeySpace, Algorithm: rainslib.Ed25519}, Key: pubKey}
	a2 := &rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}}}
	var tests = []struct {
		input      []*rainslib.AssertionSection
		keyAlgo    rainslib.SignatureAlgorithmType
		privKey    interface{}
		validSince int64
		validUntil int64
		errMsg     string
	}{
		{[]*rainslib.AssertionSection{a1}, rainslib.Ed25519, zonePrivateKey, time.Now().Unix(), time.Now().Add(86400 * time.Hour).Unix(), ""},
		{[]*rainslib.AssertionSection{a2}, rainslib.Ed25519, zonePrivateKey, time.Now().Add(-1 * time.Hour).Unix(),
			time.Now().Add(86439 * time.Hour).Unix(), ""},
		{[]*rainslib.AssertionSection{nil}, rainslib.Ed25519, nil, 0, 0, "assertion is nil"},                          //assertion is nil error
		{[]*rainslib.AssertionSection{a2}, rainslib.Ed25519, nil, 0, 0, "Was not able to sign and add the signature"}, //signSection return error
	}
	for i, test := range tests {
		err := signAssertions(test.input, test.keyAlgo, test.privKey)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && test.input[0].Signatures[0].Data == nil {
			t.Errorf("%d: signZone() did not add signature to all sections.", i)
		}
		if err == nil && (test.input[0].Signatures[0].ValidSince != test.validSince || test.input[0].Signatures[0].ValidUntil != test.validUntil) {
			t.Errorf("%d: signature validity is incorrect expectedSince=%d expectedUntil=%d actualSince=%d actualUntil=%d.", i,
				test.validSince, test.validUntil, test.input[0].Signatures[0].ValidSince, test.input[0].Signatures[0].ValidUntil)
		}
	}
}

func TestSendMessage(t *testing.T) {
	InitRainspub("test/rainspub.conf")
	rainsd.InitServer("test/server.conf", int(log.LvlInfo))
	go rainsd.Listen()
	time.Sleep(time.Second / 10)
	a := getAssertionWithTwoIPObjects()
	zone := &rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
		&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "", Content: []*rainslib.AssertionSection{a}}}}
	msg, _ := createRainsMessage(zone)
	var tests = []struct {
		input  []byte
		conns  []rainslib.ConnInfo
		errMsg string
	}{
		{msg, config.ServerAddresses, ""},
		{nil, config.ServerAddresses, "EOF"},
		{msg, []rainslib.ConnInfo{rainslib.ConnInfo{Type: rainslib.NetworkAddrType(-1)}}, "unsupported connection information type. actual=-1"},
	}
	for i, test := range tests {
		config.ServerAddresses = test.conns
		err := sendMsg(test.input, 0, 0)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		//no error or panic occurred
	}
}

func getAssertionWithTwoIPObjects() *rainslib.AssertionSection {
	return &rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			rainslib.Object{Type: rainslib.OTIP4Addr, Value: "129.132.128.139"}}}
}
