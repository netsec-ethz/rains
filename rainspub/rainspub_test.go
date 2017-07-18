package rainspub

import (
	"testing"
	"time"

	"github.com/netsec-ethz/rains/rainsd"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"

	"golang.org/x/crypto/ed25519"
)

func TestInitRainspub(t *testing.T) {
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/rainspub.conf", ""},
		{"wrongPath/rainspub.conf", "open wrongPath/rainspub.conf: no such file or directory"},       //trigger error
		{"test/rainspubWrongPath.conf", "open WrongPath/zonePrivate.key: no such file or directory"}, //trigger error
	}
	for i, test := range tests {
		err := InitRainspub(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: InitRainspub() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil {
			if parser == nil || msgParser == nil || signatureEncoder == nil {
				t.Errorf("%d: parser should not be nil.", i)
			}
		}
	}
}

func TestPublishInformation(t *testing.T) {
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/rainspub2.conf", ""},                                                        //no errors
		{"test/rainspub.conf", "open zoneFiles/chZoneFile.txt: no such file or directory"}, //load assertion error
	}
	for i, test := range tests {
		InitRainspub(test.input)
		err := PublishInformation()
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: PublishInformation() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
	}
}

func TestLoadAssertions(t *testing.T) {
	config = rainpubConfig{}
	parser = zoneFileParser.Parser{}
	var tests = []struct {
		input  string
		output []*rainslib.AssertionSection
		errMsg string
	}{
		{"test/chZoneFile.txt", []*rainslib.AssertionSection{
			&rainslib.AssertionSection{SubjectName: "ch", SubjectZone: "ch", Context: ".",
				Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "178.209.53.76"}}},
			getAssertionWithTwoIPObjects()}, ""},
		{"notExist/zonePrivate.key", nil, "open notExist/zonePrivate.key: no such file or directory"},
		{"test/malformed.conf", nil, "ZoneFile malformed wrong section type"},
	}
	for i, test := range tests {
		config.ZoneFilePath = test.input
		assertions, err := loadAssertions()
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: loadAssertions() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil {
			for j, a := range assertions {
				rainslib.CheckAssertion(a, test.output[j], t)
			}
		}
	}
}

func TestGroupAssertionsToShards(t *testing.T) {
	config = rainpubConfig{}
	a1 := &rainslib.AssertionSection{SubjectName: "ch", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "178.209.53.76"}}}
	a2 := &rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			rainslib.Object{Type: rainslib.OTIP4Addr, Value: "129.132.128.139"}}}
	a3 := &rainslib.AssertionSection{SubjectName: "uzh", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "130.60.184.132"}}}
	var tests = []struct {
		input              []*rainslib.AssertionSection
		assertionsPerShard uint
		output             *rainslib.ZoneSection
	}{
		{[]*rainslib.AssertionSection{a1, a2}, 2,
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
					Content: []*rainslib.AssertionSection{a1, a2}}}}},
		{[]*rainslib.AssertionSection{a2, a1}, 2, //test that sorting works
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
					Content: []*rainslib.AssertionSection{a1, a2}}}}},
		{[]*rainslib.AssertionSection{a3, a2, a1}, 2, //correct grouping with 2 shards and sorting
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "uzh",
					Content: []*rainslib.AssertionSection{a1, a2}},
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "ethz", RangeTo: "",
					Content: []*rainslib.AssertionSection{a3}}}}},
		{[]*rainslib.AssertionSection{a3, a2, a1}, 1, //correct grouping with >2 shards and sorting
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "ethz",
					Content: []*rainslib.AssertionSection{a1}},
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "ch", RangeTo: "uzh",
					Content: []*rainslib.AssertionSection{a2}},
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "ethz", RangeTo: "",
					Content: []*rainslib.AssertionSection{a3}}}}},
	}
	for _, test := range tests {
		config.MaxAssertionsPerShard = test.assertionsPerShard
		rainslib.CheckZone(groupAssertionsToShards(test.input), test.output, t)
	}
}

func TestSignZone(t *testing.T) {
	InitRainspub("test/rainspub.conf")
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

func TestCreateRainsMessage(t *testing.T) {
	InitRainspub("test/rainspub.conf")
	a := getAssertionWithTwoIPObjects()
	var tests = []struct {
		input  *rainslib.ZoneSection
		errMsg string
	}{
		{&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
			&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
				Content: []*rainslib.AssertionSection{a}}}}, ""},
		{&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{new(rainslib.ZoneSection)}},
			"Unsupported section type"},
	}
	for i, test := range tests {
		msg, err := createRainsMessage(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil {
			if _, err := msgParser.Decode(msg); err != nil {
				t.Errorf("%d: createRainsMessage() did not generate a valid encoding.", i)
			}
		}
	}
}

func TestSendMessage(t *testing.T) {
	InitRainspub("test/rainspub.conf")
	rainsd.InitServer("test/server.conf")
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
