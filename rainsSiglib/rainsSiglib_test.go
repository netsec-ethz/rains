package rainsSiglib

import (
	"net"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"

	"golang.org/x/crypto/ed25519"
)

func TestEncodeAndDecode(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}

	publicKey := rainslib.PublicKey{
		PublicKeyID: rainslib.PublicKeyID{
			KeySpace:  rainslib.RainsKeySpace,
			Algorithm: rainslib.Ed25519,
		},
		Key:        ed25519.PublicKey([]byte("01234567890123456789012345678901")),
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	certificate := rainslib.CertificateObject{
		Type:     rainslib.PTTLS,
		HashAlgo: rainslib.Sha256,
		Usage:    rainslib.CUEndEntity,
		Data:     []byte("certData"),
	}
	serviceInfo := rainslib.ServiceInfo{
		Name:     "lookup",
		Port:     49830,
		Priority: 1,
	}

	nameObject := rainslib.Object{Type: rainslib.OTName, Value: nameObjectContent}
	ip6Object := rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ip4Object := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	redirObject := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	nameSetObject := rainslib.Object{Type: rainslib.OTNameset, Value: rainslib.NamesetExpression("Would be an expression")}
	certObject := rainslib.Object{Type: rainslib.OTCertInfo, Value: certificate}
	serviceInfoObject := rainslib.Object{Type: rainslib.OTServiceInfo, Value: serviceInfo}
	registrarObject := rainslib.Object{Type: rainslib.OTRegistrar, Value: "Registrar information"}
	registrantObject := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}
	infraObject := rainslib.Object{Type: rainslib.OTInfraKey, Value: publicKey}
	extraObject := rainslib.Object{Type: rainslib.OTExtraKey, Value: publicKey}
	nextKey := rainslib.Object{Type: rainslib.OTNextKey, Value: publicKey}

	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			KeySpace:  rainslib.RainsKeySpace,
			Algorithm: rainslib.Ed25519,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(24 * time.Hour).Unix(),
	}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")
	_, subjectAddress3, _ := net.ParseCIDR("2001:db8::/32")

	assertion := &rainslib.AssertionSection{
		Content: []rainslib.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
			registrantObject, infraObject, extraObject, nextKey},
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
	}

	shard := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{assertion},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
	}

	zone := &rainslib.ZoneSection{
		Content:     []rainslib.MessageSectionWithSigForward{assertion, shard},
		Context:     ".",
		SubjectZone: "ch",
	}

	query := &rainslib.QuerySection{
		Context:    ".",
		Expiration: 159159,
		Name:       "ethz.ch",
		Options:    []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
		Types:      []rainslib.ObjectType{rainslib.OTIP4Addr},
	}

	notification := &rainslib.NotificationSection{
		Token: rainslib.GenerateToken(),
		Type:  rainslib.NTNoAssertionsExist,
		Data:  "Notification information",
	}

	addressAssertion1 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []rainslib.Object{nameObject},
	}

	addressAssertion2 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []rainslib.Object{redirObject, delegObject, registrantObject},
	}

	addressAssertion3 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress3,
		Context:     ".",
		Content:     []rainslib.Object{redirObject, delegObject, registrantObject},
	}

	addressZone := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion1, addressAssertion2, addressAssertion3},
	}

	addressQuery := &rainslib.AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Expiration:  7564859,
		Types:       []rainslib.ObjectType{rainslib.OTName},
		Options:     []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
	}

	message := rainslib.RainsMessage{
		Content: []rainslib.MessageSection{
			assertion,
			shard,
			zone,
			query,
			notification,
			addressAssertion1,
			addressAssertion2,
			addressAssertion3,
			addressZone,
			addressQuery,
		},
		Token:        rainslib.GenerateToken(),
		Capabilities: []rainslib.Capability{rainslib.Capability("Test"), rainslib.Capability("Yes!")},
	}

	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	pKey := rainslib.PublicKey{
		PublicKeyID: rainslib.PublicKeyID{
			KeySpace:  rainslib.RainsKeySpace,
			Algorithm: rainslib.Ed25519,
		},
		ValidSince: time.Now().Add(-24 * time.Hour).Unix(),
		ValidUntil: time.Now().Add(24 * time.Hour).Unix(),
		Key:        genPublicKey,
	}
	pKeys := make(map[rainslib.PublicKeyID][]rainslib.PublicKey)
	pKeys[rainslib.PublicKeyID{Algorithm: pKey.Algorithm}] = []rainslib.PublicKey{pKey}
	maxValidity := rainslib.MaxCacheValidity{
		AssertionValidity:        30 * time.Hour,
		ShardValidity:            30 * time.Hour,
		ZoneValidity:             30 * time.Hour,
		AddressAssertionValidity: 30 * time.Hour,
		AddressZoneValidity:      30 * time.Hour,
	}
	ok := SignMessage(&message, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the message")
	}
	ok = CheckMessageSignatures(&message, pKey, zoneFileParser.Parser{})
	if !ok {
		t.Error("Verification of message signature failed")
	}

	ok = SignSection(assertion, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the assertion")
	}
	ok = CheckSectionSignatures(assertion, pKeys, zoneFileParser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of assertion signature failed")
	}

	ok = SignSection(shard, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the shard")
	}
	ok = CheckSectionSignatures(shard, pKeys, zoneFileParser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of shard signature failed")
	}

	ok = SignSection(zone, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the zone")
	}
	ok = CheckSectionSignatures(zone, pKeys, zoneFileParser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of zone signature failed")
	}

	ok = SignSection(addressAssertion1, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressAssertion")
	}
	ok = CheckSectionSignatures(addressAssertion1, pKeys, zoneFileParser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressAssertion signature failed")
	}

	ok = SignSection(addressAssertion2, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressAssertion")
	}
	ok = CheckSectionSignatures(addressAssertion2, pKeys, zoneFileParser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressAssertion signature failed")
	}

	ok = SignSection(addressAssertion3, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressAssertion")
	}
	ok = CheckSectionSignatures(addressAssertion3, pKeys, zoneFileParser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressAssertion signature failed")
	}

	ok = SignSection(addressZone, genPrivateKey, signature, zoneFileParser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressZone")
	}
	ok = CheckSectionSignatures(addressZone, pKeys, zoneFileParser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressZone signature failed")
	}
}

func TestCheckSectionSignaturesErrors(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(zoneFileParser.Parser)
	maxVal := rainslib.MaxCacheValidity{AddressAssertionValidity: time.Hour}
	keys := make(map[rainslib.PublicKeyID][]rainslib.PublicKey)
	keys1 := make(map[rainslib.PublicKeyID][]rainslib.PublicKey)
	keys1[rainslib.PublicKeyID{Algorithm: rainslib.Ed25519}] = []rainslib.PublicKey{}
	var tests = []struct {
		input           rainslib.MessageSectionWithSig
		inputPublicKeys map[rainslib.PublicKeyID][]rainslib.PublicKey
		want            bool
	}{
		{nil, nil, false},                                                                                                                                               //msg nil
		{&rainslib.AssertionSection{}, nil, false},                                                                                                                      //pkeys nil
		{&rainslib.AssertionSection{}, keys, true},                                                                                                                      //no signatures
		{&rainslib.AssertionSection{Signatures: []rainslib.Signature{rainslib.Signature{}}, SubjectName: ":ip55:"}, keys, false},                                        //checkStringField false
		{&rainslib.AssertionSection{Signatures: []rainslib.Signature{rainslib.Signature{}}}, keys, false},                                                               //no matching algotype in keys
		{&rainslib.AssertionSection{Signatures: []rainslib.Signature{rainslib.Signature{PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519}}}}, keys1, true}, //sig expired
		{&rainslib.AssertionSection{Signatures: []rainslib.Signature{rainslib.Signature{PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
			ValidUntil: time.Now().Add(time.Second).Unix()}}}, keys1, false}, //VerifySignature invalid
	}
	for _, test := range tests {
		if CheckSectionSignatures(test.input, test.inputPublicKeys, encoder, maxVal) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, CheckSectionSignatures(test.input, test.inputPublicKeys, encoder, maxVal), test.input)
		}
	}
}

func TestCheckMessageSignaturesErrors(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(zoneFileParser.Parser)
	message := rainslib.GetMessage()
	message2 := rainslib.GetMessage()
	message2.Capabilities = []rainslib.Capability{rainslib.Capability(":ip:")}
	message3 := rainslib.GetMessage()
	message3.Signatures = []rainslib.Signature{rainslib.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}}
	var tests = []struct {
		input          *rainslib.RainsMessage
		inputPublicKey rainslib.PublicKey
		want           bool
	}{
		{nil, rainslib.PublicKey{}, false},                      //msg nil
		{&message, rainslib.PublicKey{}, false},                 //sig expired
		{&rainslib.RainsMessage{}, rainslib.PublicKey{}, false}, //no sig
		{&message2, rainslib.PublicKey{}, false},                //TextField of Content invalid
		{&message3, rainslib.PublicKey{}, false},                //signature invalid
	}
	for _, test := range tests {
		if CheckMessageSignatures(test.input, test.inputPublicKey, encoder) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, CheckMessageSignatures(test.input, test.inputPublicKey, encoder), test.input)
		}
	}
}

func TestSignSection(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(zoneFileParser.Parser)
	sections := rainslib.GetMessage().Content
	_, pkey, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		input           rainslib.MessageSectionWithSig
		inputPrivateKey interface{}
		inputSig        rainslib.Signature
		want            bool
	}{
		{nil, nil, rainslib.Signature{}, false},
		{
			sections[0].(rainslib.MessageSectionWithSig),
			pkey,
			rainslib.Signature{
				PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
				ValidUntil:  time.Now().Add(time.Second).Unix(),
			},
			true,
		},
		{sections[0].(rainslib.MessageSectionWithSig), pkey, rainslib.Signature{ValidUntil: time.Now().Unix() - 100}, false},
		{&rainslib.AssertionSection{SubjectName: ":ip:"}, pkey, rainslib.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
		{sections[0].(rainslib.MessageSectionWithSig), nil, rainslib.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
	}
	for _, test := range tests {
		if SignSection(test.input, test.inputPrivateKey, test.inputSig, encoder) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, SignSection(test.input, test.inputPrivateKey, test.inputSig, encoder), test.input)
		}
		if test.want && test.input.Sigs(rainslib.RainsKeySpace)[0].Data == nil {
			t.Error("msg.Signature does not contain generated signature data")
		}
	}
}

func TestSignMessage(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(zoneFileParser.Parser)
	message := rainslib.GetMessage()
	_, pkey, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		input           *rainslib.RainsMessage
		inputPrivateKey interface{}
		inputSig        rainslib.Signature
		want            bool
	}{
		{nil, nil, rainslib.Signature{}, false},
		{
			&message,
			pkey,
			rainslib.Signature{
				PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
				ValidUntil:  time.Now().Add(time.Second).Unix(),
			},
			true,
		},
		{&message, pkey, rainslib.Signature{ValidUntil: time.Now().Add(time.Second).Unix() - 100}, false},
		{&rainslib.RainsMessage{Capabilities: []rainslib.Capability{rainslib.Capability(":ip:")}}, pkey,
			rainslib.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
		{&rainslib.RainsMessage{}, nil, rainslib.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
	}
	for _, test := range tests {
		if SignMessage(test.input, test.inputPrivateKey, test.inputSig, encoder) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, SignMessage(test.input, test.inputPrivateKey, test.inputSig, encoder), test.input)
		}
		if test.want && test.input.Signatures[0].Data == nil {
			t.Error("msg.Signature does not contain generated signature data")
		}
	}
}

func TestCheckMessageStringFields(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	message := rainslib.GetMessage()
	var tests = []struct {
		input *rainslib.RainsMessage
		want  bool
	}{
		{nil, false},
		{&message, true},
		{&rainslib.RainsMessage{Capabilities: []rainslib.Capability{rainslib.Capability(":ip:")}}, false},
		{&rainslib.RainsMessage{Content: []rainslib.MessageSection{&rainslib.AssertionSection{SubjectName: ":ip:"}}}, false},
	}
	for _, test := range tests {
		if checkMessageStringFields(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkMessageStringFields(test.input), test.input)
		}
	}
}

func TestCheckStringFields(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	sections := rainslib.GetMessage().Content
	var tests = []struct {
		input rainslib.MessageSection
		want  bool
	}{
		{nil, false},
		{sections[0], true},
		{sections[1], true},
		{sections[2], true},
		{sections[3], true},
		{sections[4], true},
		{sections[5], true},
		{sections[6], true},
		{sections[8], true},
		{sections[9], true},
		{&rainslib.AssertionSection{SubjectName: ":ip:"}, false},
		{&rainslib.AssertionSection{Context: ":ip:"}, false},
		{&rainslib.AssertionSection{SubjectZone: ":ip:"}, false},
		{&rainslib.AssertionSection{Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTRegistrar, Value: ":ip55:"}}}, false},
		{&rainslib.ShardSection{Context: ":ip:"}, false},
		{&rainslib.ShardSection{SubjectZone: ":ip:"}, false},
		{&rainslib.ShardSection{RangeFrom: ":ip:"}, false},
		{&rainslib.ShardSection{RangeTo: ":ip:"}, false},
		{&rainslib.ShardSection{Content: []*rainslib.AssertionSection{&rainslib.AssertionSection{SubjectName: ":ip:"}}}, false},
		{&rainslib.ZoneSection{SubjectZone: ":ip:"}, false},
		{&rainslib.ZoneSection{Context: ":ip:"}, false},
		{&rainslib.ZoneSection{Content: []rainslib.MessageSectionWithSigForward{&rainslib.AssertionSection{SubjectName: ":ip:"}}}, false},
		{&rainslib.QuerySection{Context: ":ip:"}, false},
		{&rainslib.QuerySection{Name: ":ip:"}, false},
		{&rainslib.NotificationSection{Data: ":ip:"}, false},
		{&rainslib.AddressQuerySection{Context: ":ip:"}, false},
		{&rainslib.AddressAssertionSection{Context: ":ip:"}, false},
		{&rainslib.AddressAssertionSection{Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTRegistrant, Value: ":ip55:"}}}, false},
		{&rainslib.AddressZoneSection{Context: ":ip:"}, false},
		{&rainslib.AddressZoneSection{Content: []*rainslib.AddressAssertionSection{&rainslib.AddressAssertionSection{Context: ":ip:"}}}, false},
	}
	for _, test := range tests {
		if checkStringFields(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkStringFields(test.input), test.input)
		}
	}
}

func TestCheckObjectFields(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	var tests = []struct {
		input []rainslib.Object
		want  bool
	}{
		{nil, true},
		{[]rainslib.Object{}, true},
		{rainslib.GetAllValidObjects(), true},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTName, Value: rainslib.NameObject{Name: ":ip55:"}}}, false},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTRedirection, Value: ":ip55:"}}, false},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTNameset, Value: rainslib.NamesetExpression(":ip55:")}}, false},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTServiceInfo, Value: rainslib.ServiceInfo{Name: ":ip55:"}}}, false},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTRegistrar, Value: ":ip55:"}}, false},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.OTRegistrant, Value: ":ip55:"}}, false},
		{[]rainslib.Object{rainslib.Object{Type: rainslib.ObjectType(-1), Value: nil}}, false},
	}
	for _, test := range tests {
		if checkObjectFields(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkObjectFields(test.input), test.input)
		}
	}
}

func TestCheckCapabilites(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	var tests = []struct {
		input []rainslib.Capability
		want  bool
	}{
		{nil, true},
		{[]rainslib.Capability{}, true},
		{[]rainslib.Capability{rainslib.Capability("")}, true},
		{[]rainslib.Capability{rainslib.Capability("Good")}, true},
		{[]rainslib.Capability{rainslib.Capability(":ip: bad")}, false},
		{[]rainslib.Capability{rainslib.Capability(":ip:")}, false},
		{[]rainslib.Capability{rainslib.Capability("bad :ip: test")}, false},
		{[]rainslib.Capability{rainslib.Capability("bad\t:ip:\ttest")}, false},
		{[]rainslib.Capability{rainslib.Capability("bad\n:ip:\ntest")}, false},
		{[]rainslib.Capability{rainslib.Capability("bad\n:ip:\ttest")}, false},
		{[]rainslib.Capability{rainslib.Capability("bad test :ip:")}, false},
		{[]rainslib.Capability{rainslib.Capability("bad test\n\n :ip:")}, false},
		{[]rainslib.Capability{rainslib.Capability("as:Good:dh")}, true},
		{[]rainslib.Capability{rainslib.Capability("as:Good: dh")}, true},
		{[]rainslib.Capability{rainslib.Capability("as :Good:dh")}, true},
		{[]rainslib.Capability{rainslib.Capability(" :: ")}, true},
		{[]rainslib.Capability{rainslib.Capability("::")}, true},
		{[]rainslib.Capability{rainslib.Capability("::"), rainslib.Capability(":ip4:Good")}, true},
		{[]rainslib.Capability{rainslib.Capability("::"), rainslib.Capability(":ip4: Good")}, false},
	}
	for _, test := range tests {
		if checkCapabilites(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkCapabilites(test.input), test.input)
		}
	}
}

func TestContainsZoneFileType(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	var tests = []struct {
		input string
		want  bool
	}{
		{"", false},
		{"Good", false},
		{":ip:", true},
		{":ip: bad", true},
		{"bad test\n\n :ip:", true},
		{"bad :ip: test", true},
		{"bad\t:ip:\ttest", true},
		{"bad\n:ip:\ntest", true},
		{"bad\n:ip:\ttest", true},
		{"bad test :ip:", true},
		{"as:Good:dh", false},
		{"as:Good: dh", false},
		{"as :Good:dh", false},
		{":ip:d", false},
		{" :: ", false},
		{"::", false},
	}
	for _, test := range tests {
		if containsZoneFileType(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, containsZoneFileType(test.input), test.input)
		}
	}
}

var result bool

func BenchmarkSignAssertions(b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(zoneFileParser.Parser)
	_, pkey, _ := ed25519.GenerateKey(nil)
	assertion := rainslib.GetMessage().Content[0].(rainslib.MessageSectionWithSig)
	sig := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		for i := 0; i < 10000; i++ {
			result = SignSectionUnsafe(assertion, pkey, sig, encoder)
		}
	}
}

func benchmarkSignShard(nofAssertions int, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(zoneFileParser.Parser)
	_, pkey, _ := ed25519.GenerateKey(nil)
	assertion := rainslib.GetMessage().Content[0].(*rainslib.AssertionSection)
	shard := rainslib.GetMessage().Content[1].(*rainslib.ShardSection)
	for i := 1; i < nofAssertions; i++ {
		shard.Content = append(shard.Content, assertion)
	}
	sig := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		result = SignSectionUnsafe(shard, pkey, sig, encoder)
	}
}

func BenchmarkSignShard10(b *testing.B)  { benchmarkSignShard(10, b) }
func BenchmarkSignShard100(b *testing.B) { benchmarkSignShard(100, b) }

//Assertions are equally distributed among shards. Zone only contains shards as assertions are
//contained in shards.
func benchmarkSignZone(nofShards, nofAssertionsPerShard int, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(zoneFileParser.Parser)
	_, pkey, _ := ed25519.GenerateKey(nil)
	assertion := rainslib.GetMessage().Content[0].(*rainslib.AssertionSection)
	shard := rainslib.GetMessage().Content[1].(*rainslib.ShardSection)
	zone := rainslib.GetMessage().Content[2].(*rainslib.ZoneSection)
	for i := 1; i < nofAssertionsPerShard; i++ {
		shard.Content = append(shard.Content, assertion)
	}
	for i := 1; i < nofShards; i++ {
		zone.Content = append(zone.Content, shard)
	}
	sig := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		result = SignSectionUnsafe(zone, pkey, sig, encoder)
	}
}

func BenchmarkSignZone10_100(b *testing.B)  { benchmarkSignZone(10, 100, b) }
func BenchmarkSignShard100_10(b *testing.B) { benchmarkSignZone(100, 10, b) }
