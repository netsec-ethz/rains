package publisher

import (
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

func benchmarkAddMetaData(zonefileName string, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	parser := new(zonefile.Parser)
	zone, err := parser.LoadZone(zonefileName)
	if err != nil {
		b.Error(err)
		return
	}
	nofPshards, nofAssertions := 0, 0
	for _, s := range zone.Content {
		switch s.(type) {
		case *section.Assertion:
			nofAssertions++
		case *section.Pshard:
			nofPshards++
		}
	}
	conf := MetaDataConfig{
		AddSigMetaDataToAssertions: true,
		AddSigMetaDataToPshards:    true,
		AddSigMetaDataToShards:     true,
		AddSignatureMetaData:       true,
		KeyPhase:                   1,
		SignatureAlgorithm:         algorithmTypes.Ed25519,
		SigSigningInterval:         time.Hour,
		SigValidSince:              time.Now().Unix(),
		SigValidUntil:              time.Now().Add(4 * time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		addSignatureMetaData(zone, nofAssertions, nofPshards, conf)
	}
}

//benchmarkSharding expects as input a path to a zonefile containing a zone
//whose contained assertions are sorted.
func benchmarkSharding(zonefileName string, shardSize int, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	parser := new(zonefile.Parser)
	zone, err := parser.LoadZone(zonefileName)
	if err != nil {
		b.Error(err)
		return
	}
	assertions := []*section.Assertion{}
	for _, s := range zone.Content {
		switch assertion := s.(type) {
		case *section.Assertion:
			assertions = append(assertions, assertion)
		}
	}
	conf := ShardingConfig{
		DoSharding:         true,
		KeepExistingShards: false,
		MaxShardSize:       shardSize,
	}
	for n := 0; n < b.N; n++ {
		DoSharding(zone.Context, zone.SubjectZone, assertions, []*section.Shard{}, conf, false)
	}
}

//benchmarkPsharding expects as input a path to a zonefile containing a zone
//whose contained assertions are sorted.
func benchmarkPsharding(zonefileName string, shardSize, nofHashfunc int, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	parser := new(zonefile.Parser)
	zone, err := parser.LoadZone(zonefileName)
	if err != nil {
		b.Error(err)
		return
	}
	assertions := []*section.Assertion{}
	for _, s := range zone.Content {
		switch assertion := s.(type) {
		case *section.Assertion:
			assertions = append(assertions, assertion)
		}
	}
	conf := PShardingConfig{
		BloomFilterConf: BloomFilterConfig{
			BFOpMode:         section.KirschMitzenmacher1,
			BloomFilterSize:  1000,
			Hashfamily:       []algorithmTypes.Hash{algorithmTypes.Fnv128},
			NofHashFunctions: nofHashfunc,
		},
		DoPsharding:            true,
		KeepExistingPshards:    false,
		NofAssertionsPerPshard: shardSize,
	}
	for n := 0; n < b.N; n++ {
		DoPsharding(zone.Context, zone.SubjectZone, assertions, []*section.Pshard{}, conf, false)
	}
}

//TODO CFE Fix tests for rainspub

/*
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
	zonePrivateKey, _ := loadPrivateKey("test/zonePrivate.key")
	a := getAssertionWithTwoIPObjects()
	var tests = []struct {
		input   *section.ZoneSection
		keyAlgo algorithmTypes.SignatureAlgorithmType
		privKey interface{}
		errMsg  string
	}{
		{&section.ZoneSection{SubjectZone: "ch", Context: ".", Content: []section.MessageSectionWithSigForward{
			&section.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
				Content: []*section.AssertionSection{a}}}}, keys.Ed25519, zonePrivateKey, ""},
		{nil, keys.Ed25519, nil, "zone is nil"},                                                      //zone is nil error
		{new(section.ZoneSection), keys.Ed25519, nil, "Was not able to sign and add the signature"}, //signSection return error
		{&section.ZoneSection{SubjectZone: "ch", Context: ".", Content: []section.MessageSectionWithSigForward{
			new(section.AssertionSection)}}, keys.Ed25519, zonePrivateKey,
			"Zone contained unexpected type expected=*ShardSection actual=*section.AssertionSection"}, //invalid zone content error
	}
	for i, test := range tests {
		err := signZone(test.input, test.keyAlgo, test.privKey)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && (test.input.Signatures[0].Data == nil || test.input.Content[0].Sigs(keys.RainsKeySpace)[0].Data == nil ||
			test.input.Content[0].(*section.ShardSection).Content[0].Signatures[0].Data == nil) {
			t.Errorf("%d: signZone() did not add signature to all section.", i)
		}
	}
}

func TestSignShard(t *testing.T) {
	InitRainspub("test/rainspub.conf")
	a := getAssertionWithTwoIPObjects()
	var tests = []struct {
		input   *section.ShardSection
		keyAlgo algorithmTypes.SignatureAlgorithmType
		privKey interface{}
		errMsg  string
	}{
		{&section.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
			Content: []*section.AssertionSection{a}}, keys.Ed25519, zonePrivateKey, ""},
		{nil, keys.Ed25519, nil, "shard is nil"},                                                      //shard is nil error
		{new(section.ShardSection), keys.Ed25519, nil, "Was not able to sign and add the signature"}, //signSection return error
	}
	for i, test := range tests {
		err := signShard(test.input, test.keyAlgo, test.privKey)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && (test.input.Content[0].Sigs(keys.RainsKeySpace)[0].Data == nil ||
			test.input.Content[0].Signatures[0].Data == nil) {
			t.Errorf("%d: signZone() did not add signature to all section.", i)
		}
	}
}

func TestSignAssertion(t *testing.T) {
	InitRainspub("test/rainspub.conf")
	a1 := getAssertionWithTwoIPObjects()
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := keys.PublicKey{PublicKeyID: keys.PublicKeyID{KeySpace: keys.RainsKeySpace, Algorithm: keys.Ed25519}, Key: pubKey}
	a2 := &section.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []object.Object{object.Object{Type: object.OTDelegation, Value: publicKey}}}
	var tests = []struct {
		input      []*section.AssertionSection
		keyAlgo    algorithmTypes.SignatureAlgorithmType
		privKey    interface{}
		validSince int64
		validUntil int64
		errMsg     string
	}{
		{[]*section.AssertionSection{a1}, keys.Ed25519, zonePrivateKey, time.Now().Unix(), time.Now().Add(86400 * time.Hour).Unix(), ""},
		{[]*section.AssertionSection{a2}, keys.Ed25519, zonePrivateKey, time.Now().Add(-1 * time.Hour).Unix(),
			time.Now().Add(86439 * time.Hour).Unix(), ""},
		{[]*section.AssertionSection{nil}, keys.Ed25519, nil, 0, 0, "assertion is nil"},                          //assertion is nil error
		{[]*section.AssertionSection{a2}, keys.Ed25519, nil, 0, 0, "Was not able to sign and add the signature"}, //signSection return error
	}
	for i, test := range tests {
		err := signAssertions(test.input, test.keyAlgo, test.privKey)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: signZone() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && test.input[0].Signatures[0].Data == nil {
			t.Errorf("%d: signZone() did not add signature to all section.", i)
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
	zone := &section.ZoneSection{SubjectZone: "ch", Context: ".", Content: []section.MessageSectionWithSigForward{
		&section.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "", Content: []*section.AssertionSection{a}}}}
	msg, _ := createRainsMessage(zone)
	var tests = []struct {
		input  []byte
		conns  []connection.ConnInfo
		errMsg string
	}{
		{msg, config.ServerAddresses, ""},
		{nil, config.ServerAddresses, "EOF"},
		{msg, []connection.ConnInfo{connection.ConnInfo{Type: connection.NetworkAddrType(-1)}}, "unsupported connection information type. actual=-1"},
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

func getAssertionWithTwoIPObjects() *section.AssertionSection {
	return &section.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []object.Object{object.Object{Type: object.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			object.Object{Type: object.OTIP4Addr, Value: "129.132.128.139"}}}
}*/
