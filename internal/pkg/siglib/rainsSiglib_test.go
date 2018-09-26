package siglib

import (
	"io/ioutil"
	"net"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	parser "github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"golang.org/x/crypto/ed25519"
)

func TestEncodeAndDecode(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	nameObjectContent := object.NameObject{
		Name:  "ethz2.ch",
		Types: []object.ObjectType{object.OTIP4Addr, object.OTIP6Addr},
	}

	publicKey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: keys.Ed25519,
		},
		Key:        ed25519.PublicKey([]byte("01234567890123456789012345678901")),
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	certificate := object.CertificateObject{
		Type:     object.PTTLS,
		HashAlgo: algorithmTypes.Sha256,
		Usage:    object.CUEndEntity,
		Data:     []byte("certData"),
	}
	serviceInfo := object.ServiceInfo{
		Name:     "lookup",
		Port:     49830,
		Priority: 1,
	}

	nameObject := object.Object{Type: object.OTName, Value: nameObjectContent}
	ip6Object := object.Object{Type: object.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ip4Object := object.Object{Type: object.OTIP4Addr, Value: "127.0.0.1"}
	redirObject := object.Object{Type: object.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := object.Object{Type: object.OTDelegation, Value: publicKey}
	nameSetObject := object.Object{Type: object.OTNameset, Value: object.NamesetExpression("Would be an expression")}
	certObject := object.Object{Type: object.OTCertInfo, Value: certificate}
	serviceInfoObject := object.Object{Type: object.OTServiceInfo, Value: serviceInfo}
	registrarObject := object.Object{Type: object.OTRegistrar, Value: "Registrar information"}
	registrantObject := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}
	infraObject := object.Object{Type: object.OTInfraKey, Value: publicKey}
	extraObject := object.Object{Type: object.OTExtraKey, Value: publicKey}
	nextKey := object.Object{Type: object.OTNextKey, Value: publicKey}

	signature := signature.Signature{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: keys.Ed25519,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(24 * time.Hour).Unix(),
	}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")
	_, subjectAddress3, _ := net.ParseCIDR("2001:db8::/32")

	assertion := &sections.AssertionSection{
		Content: []object.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
			registrantObject, infraObject, extraObject, nextKey},
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
	}

	shard := &sections.ShardSection{
		Content:     []*sections.AssertionSection{assertion},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
	}

	zone := &sections.ZoneSection{
		Content:     []sections.MessageSectionWithSigForward{assertion, shard},
		Context:     ".",
		SubjectZone: "ch",
	}

	query := &sections.QuerySection{
		Context:    ".",
		Expiration: 159159,
		Name:       "ethz.ch",
		Options:    []sections.QueryOption{sections.QOMinE2ELatency, sections.QOMinInfoLeakage},
		Types:      []object.ObjectType{object.OTIP4Addr},
	}

	notification := &sections.NotificationSection{
		Token: token.GenerateToken(),
		Type:  sections.NTNoAssertionsExist,
		Data:  "Notification information",
	}

	addressAssertion1 := &sections.AddressAssertionSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []object.Object{nameObject},
	}

	addressAssertion2 := &sections.AddressAssertionSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []object.Object{redirObject, delegObject, registrantObject},
	}

	addressAssertion3 := &sections.AddressAssertionSection{
		SubjectAddr: subjectAddress3,
		Context:     ".",
		Content:     []object.Object{redirObject, delegObject, registrantObject},
	}

	addressZone := &sections.AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*sections.AddressAssertionSection{addressAssertion1, addressAssertion2, addressAssertion3},
	}

	addressQuery := &sections.AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Expiration:  7564859,
		Types:       []object.ObjectType{object.OTName},
		Options:     []sections.QueryOption{sections.QOMinE2ELatency, sections.QOMinInfoLeakage},
	}

	message := message.RainsMessage{
		Content: []sections.MessageSection{
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
		Token:        token.GenerateToken(),
		Capabilities: []message.Capability{message.Capability("Test"), message.Capability("Yes!")},
	}

	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	pKey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: keys.Ed25519,
		},
		ValidSince: time.Now().Add(-24 * time.Hour).Unix(),
		ValidUntil: time.Now().Add(24 * time.Hour).Unix(),
		Key:        genPublicKey,
	}
	pKeys := make(map[keys.PublicKeyID][]keys.PublicKey)
	pKeys[keys.PublicKeyID{Algorithm: pKey.Algorithm}] = []keys.PublicKey{pKey}
	maxValidity := object.MaxCacheValidity{
		AssertionValidity:        30 * time.Hour,
		ShardValidity:            30 * time.Hour,
		ZoneValidity:             30 * time.Hour,
		AddressAssertionValidity: 30 * time.Hour,
		AddressZoneValidity:      30 * time.Hour,
	}
	ok := SignMessage(&message, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the message")
	}
	ok = CheckMessageSignatures(&message, pKey, parser.Parser{})
	if !ok {
		t.Error("Verification of message signature failed")
	}

	ok = SignSection(assertion, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the assertion")
	}
	ok = CheckSectionSignatures(assertion, pKeys, parser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of assertion signature failed")
	}

	ok = SignSection(shard, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the shard")
	}
	ok = CheckSectionSignatures(shard, pKeys, parser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of shard signature failed")
	}

	ok = SignSection(zone, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the zone")
	}
	ok = CheckSectionSignatures(zone, pKeys, parser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of zone signature failed")
	}

	ok = SignSection(addressAssertion1, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressAssertion")
	}
	ok = CheckSectionSignatures(addressAssertion1, pKeys, parser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressAssertion signature failed")
	}

	ok = SignSection(addressAssertion2, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressAssertion")
	}
	ok = CheckSectionSignatures(addressAssertion2, pKeys, parser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressAssertion signature failed")
	}

	ok = SignSection(addressAssertion3, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressAssertion")
	}
	ok = CheckSectionSignatures(addressAssertion3, pKeys, parser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressAssertion signature failed")
	}

	ok = SignSection(addressZone, genPrivateKey, signature, parser.Parser{})
	if !ok {
		t.Error("Was not able to generate and add a signature to the addressZone")
	}
	ok = CheckSectionSignatures(addressZone, pKeys, parser.Parser{}, maxValidity)
	if !ok {
		t.Error("Verification of addressZone signature failed")
	}
}

func TestCheckSectionSignaturesErrors(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(parser.Parser)
	maxVal := object.MaxCacheValidity{AddressAssertionValidity: time.Hour}
	keys := make(map[keys.PublicKeyID][]keys.PublicKey)
	keys1 := make(map[keys.PublicKeyID][]keys.PublicKey)
	keys1[keys.PublicKeyID{Algorithm: keys.Ed25519}] = []keys.PublicKey{}
	var tests = []struct {
		input           sections.MessageSectionWithSig
		inputPublicKeys map[keys.PublicKeyID][]keys.PublicKey
		want            bool
	}{
		{nil, nil, false},                                                                                                                                         //msg nil
		{&sections.AssertionSection{}, nil, false},                                                                                                                //pkeys nil
		{&sections.AssertionSection{}, keys, true},                                                                                                                //no signatures
		{&sections.AssertionSection{Signatures: []signature.Signature{signature.Signature{}}, SubjectName: ":ip55:"}, keys, false},                                //checkStringField false
		{&sections.AssertionSection{Signatures: []signature.Signature{signature.Signature{}}}, keys, false},                                                       //no matching algotype in keys
		{&sections.AssertionSection{Signatures: []signature.Signature{signature.Signature{PublicKeyID: keys.PublicKeyID{Algorithm: keys.Ed25519}}}}, keys1, true}, //sig expired
		{&sections.AssertionSection{Signatures: []signature.Signature{signature.Signature{PublicKeyID: keys.PublicKeyID{Algorithm: keys.Ed25519},
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
	encoder := new(parser.Parser)
	message := object.GetMessage()
	message2 := object.GetMessage()
	message2.Capabilities = []message.Capability{message.Capability(":ip:")}
	message3 := object.GetMessage()
	message3.Signatures = []signature.Signature{signature.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}}
	var tests = []struct {
		input          *message.RainsMessage
		inputPublicKey keys.PublicKey
		want           bool
	}{
		{nil, keys.PublicKey{}, false},                     //msg nil
		{&message, keys.PublicKey{}, false},                //sig expired
		{&message.RainsMessage{}, keys.PublicKey{}, false}, //no sig
		{&message2, keys.PublicKey{}, false},               //TextField of Content invalid
		{&message3, keys.PublicKey{}, false},               //signature invalid
	}
	for _, test := range tests {
		if CheckMessageSignatures(test.input, test.inputPublicKey, encoder) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, CheckMessageSignatures(test.input, test.inputPublicKey, encoder), test.input)
		}
	}
}

func TestSignSection(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(parser.Parser)
	sections := object.GetMessage().Content
	_, pkey, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		input           sections.MessageSectionWithSig
		inputPrivateKey interface{}
		inputSig        signature.Signature
		want            bool
	}{
		{nil, nil, signature.Signature{}, false},
		{
			sections[0].(sections.MessageSectionWithSig),
			pkey,
			signature.Signature{
				PublicKeyID: keys.PublicKeyID{Algorithm: keys.Ed25519},
				ValidUntil:  time.Now().Add(time.Second).Unix(),
			},
			true,
		},
		{sections[0].(sections.MessageSectionWithSig), pkey, signature.Signature{ValidUntil: time.Now().Unix() - 100}, false},
		{&sections.AssertionSection{SubjectName: ":ip:"}, pkey, signature.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
		{sections[0].(sections.MessageSectionWithSig), nil, signature.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
	}
	for _, test := range tests {
		if SignSection(test.input, test.inputPrivateKey, test.inputSig, encoder) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, SignSection(test.input, test.inputPrivateKey, test.inputSig, encoder), test.input)
		}
		if test.want && test.input.Sigs(keys.RainsKeySpace)[0].Data == nil {
			t.Error("msg.Signature does not contain generated signature data")
		}
	}
}

func TestSignMessage(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(parser.Parser)
	message := object.GetMessage()
	_, pkey, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		input           *message.RainsMessage
		inputPrivateKey interface{}
		inputSig        signature.Signature
		want            bool
	}{
		{nil, nil, signature.Signature{}, false},
		{
			&message,
			pkey,
			signature.Signature{
				PublicKeyID: keys.PublicKeyID{Algorithm: keys.Ed25519},
				ValidUntil:  time.Now().Add(time.Second).Unix(),
			},
			true,
		},
		{&message, pkey, signature.Signature{ValidUntil: time.Now().Add(time.Second).Unix() - 100}, false},
		{&message.RainsMessage{Capabilities: []message.Capability{message.Capability(":ip:")}}, pkey,
			signature.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
		{&message.RainsMessage{}, nil, signature.Signature{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
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
	message := object.GetMessage()
	var tests = []struct {
		input *message.RainsMessage
		want  bool
	}{
		{nil, false},
		{&message, true},
		{&message.RainsMessage{Capabilities: []message.Capability{message.Capability(":ip:")}}, false},
		{&message.RainsMessage{Content: []sections.MessageSection{&sections.AssertionSection{SubjectName: ":ip:"}}}, false},
	}
	for _, test := range tests {
		if checkMessageStringFields(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkMessageStringFields(test.input), test.input)
		}
	}
}

func TestCheckStringFields(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	sections := object.GetMessage().Content
	var tests = []struct {
		input sections.MessageSection
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
		{&sections.AssertionSection{SubjectName: ":ip:"}, false},
		{&sections.AssertionSection{Context: ":ip:"}, false},
		{&sections.AssertionSection{SubjectZone: ":ip:"}, false},
		{&sections.AssertionSection{Content: []object.Object{object.Object{Type: object.OTRegistrar, Value: ":ip55:"}}}, false},
		{&sections.ShardSection{Context: ":ip:"}, false},
		{&sections.ShardSection{SubjectZone: ":ip:"}, false},
		{&sections.ShardSection{RangeFrom: ":ip:"}, false},
		{&sections.ShardSection{RangeTo: ":ip:"}, false},
		{&sections.ShardSection{Content: []*sections.AssertionSection{&sections.AssertionSection{SubjectName: ":ip:"}}}, false},
		{&sections.ZoneSection{SubjectZone: ":ip:"}, false},
		{&sections.ZoneSection{Context: ":ip:"}, false},
		{&sections.ZoneSection{Content: []sections.MessageSectionWithSigForward{&sections.AssertionSection{SubjectName: ":ip:"}}}, false},
		{&sections.QuerySection{Context: ":ip:"}, false},
		{&sections.QuerySection{Name: ":ip:"}, false},
		{&sections.NotificationSection{Data: ":ip:"}, false},
		{&sections.AddressQuerySection{Context: ":ip:"}, false},
		{&sections.AddressAssertionSection{Context: ":ip:"}, false},
		{&sections.AddressAssertionSection{Content: []object.Object{object.Object{Type: object.OTRegistrant, Value: ":ip55:"}}}, false},
		{&sections.AddressZoneSection{Context: ":ip:"}, false},
		{&sections.AddressZoneSection{Content: []*sections.AddressAssertionSection{&sections.AddressAssertionSection{Context: ":ip:"}}}, false},
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
		input []object.Object
		want  bool
	}{
		{nil, true},
		{[]object.Object{}, true},
		{object.GetAllValidObjects(), true},
		{[]object.Object{object.Object{Type: object.OTName, Value: object.NameObject{Name: ":ip55:"}}}, false},
		{[]object.Object{object.Object{Type: object.OTRedirection, Value: ":ip55:"}}, false},
		{[]object.Object{object.Object{Type: object.OTNameset, Value: object.NamesetExpression(":ip55:")}}, false},
		{[]object.Object{object.Object{Type: object.OTServiceInfo, Value: object.ServiceInfo{Name: ":ip55:"}}}, false},
		{[]object.Object{object.Object{Type: object.OTRegistrar, Value: ":ip55:"}}, false},
		{[]object.Object{object.Object{Type: object.OTRegistrant, Value: ":ip55:"}}, false},
		{[]object.Object{object.Object{Type: object.ObjectType(-1), Value: nil}}, false},
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
		input []message.Capability
		want  bool
	}{
		{nil, true},
		{[]message.Capability{}, true},
		{[]message.Capability{message.Capability("")}, true},
		{[]message.Capability{message.Capability("Good")}, true},
		{[]message.Capability{message.Capability(":ip: bad")}, false},
		{[]message.Capability{message.Capability(":ip:")}, false},
		{[]message.Capability{message.Capability("bad :ip: test")}, false},
		{[]message.Capability{message.Capability("bad\t:ip:\ttest")}, false},
		{[]message.Capability{message.Capability("bad\n:ip:\ntest")}, false},
		{[]message.Capability{message.Capability("bad\n:ip:\ttest")}, false},
		{[]message.Capability{message.Capability("bad test :ip:")}, false},
		{[]message.Capability{message.Capability("bad test\n\n :ip:")}, false},
		{[]message.Capability{message.Capability("as:Good:dh")}, true},
		{[]message.Capability{message.Capability("as:Good: dh")}, true},
		{[]message.Capability{message.Capability("as :Good:dh")}, true},
		{[]message.Capability{message.Capability(" :: ")}, true},
		{[]message.Capability{message.Capability("::")}, true},
		{[]message.Capability{message.Capability("::"), message.Capability(":ip4:Good")}, true},
		{[]message.Capability{message.Capability("::"), message.Capability(":ip4: Good")}, false},
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

//Reads a zonefile and signs all contained assertions
func benchmarkSignAssertions(zonefileName string, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())

	parser := new(parser.Parser)
	data, err := ioutil.ReadFile(zonefileName)
	if err != nil {
		log.Error("Was not able to read zonefile", "error", err)
		return
	}
	assertions, err := parser.Decode(data)
	if err != nil {
		log.Error("Was not able to decode zonefile", "error", err)
		return
	}
	_, pkey, _ := ed25519.GenerateKey(nil)
	sig := signature.Signature{
		PublicKeyID: keys.PublicKeyID{Algorithm: keys.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		for _, assertion := range assertions {
			result = SignSectionUnsafe(assertion, pkey, sig, parser)
		}
	}
}

func BenchmarkSignAssertion10000(b *testing.B)  { benchmarkSignAssertions("test/zonefile10000", b) }
func BenchmarkSignAssertion100000(b *testing.B) { benchmarkSignAssertions("test/zonefile100000", b) }

//BenchmarkSignAssertionDeleg10000 has 40000 entries, a deleg, redir, srv and
//ip4 for each Delegated zone
func BenchmarkSignAssertionDeleg10000(b *testing.B) {
	benchmarkSignAssertions("test/zonefileDeleg10000", b)
}
func BenchmarkSignAssertionDeleg100000(b *testing.B) {
	benchmarkSignAssertions("test/zonefileDeleg100000", b)
}

//Shard ranges are not chosen correctly
func benchmarkSignShard(zonefileName string, assertionsPerShard int, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	parser := new(parser.Parser)
	data, err := ioutil.ReadFile(zonefileName)
	if err != nil {
		log.Error("Was not able to read zonefile", "error", err)
		return
	}
	assertions, err := parser.Decode(data)
	if err != nil {
		log.Error("Was not able to decode zonefile", "error", err)
		return
	}
	shards := shardAssertions(assertions, assertionsPerShard)
	_, pkey, _ := ed25519.GenerateKey(nil)
	sig := signature.Signature{
		PublicKeyID: keys.PublicKeyID{Algorithm: keys.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		for _, shard := range shards {
			result = SignSectionUnsafe(shard, pkey, sig, parser)
		}
	}
}

//10000 shards are signed containing each 10 assertions
func BenchmarkSignShard10(b *testing.B) { benchmarkSignShard("test/zonefile100000", 10, b) }

//1000 shards are signed containing each 100 assertions

func BenchmarkSignShard100(b *testing.B) { benchmarkSignShard("test/zonefile100000", 100, b) }

//100 shards are signed containing each 1000 assertions

func BenchmarkSignShard1000(b *testing.B) { benchmarkSignShard("test/zonefile100000", 1000, b) }

//Assertions are equally distributed among shards. Zone only contains shards as assertions are
//contained in shards.
func benchmarkSignZone(zonefileName string, assertionsPerShard int, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())
	parser := new(parser.Parser)
	data, err := ioutil.ReadFile(zonefileName)
	if err != nil {
		log.Error("Was not able to read zonefile", "error", err)
		return
	}
	assertions, err := parser.Decode(data)
	if err != nil {
		log.Error("Was not able to decode zonefile", "error", err)
		return
	}
	shards := shardAssertions(assertions, assertionsPerShard)
	zone := &sections.ZoneSection{
		Context:     assertions[0].Context,
		SubjectZone: assertions[0].SubjectZone,
		Content:     shards,
	}
	_, pkey, _ := ed25519.GenerateKey(nil)
	sig := signature.Signature{
		PublicKeyID: keys.PublicKeyID{Algorithm: keys.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		result = SignSectionUnsafe(zone, pkey, sig, parser)
	}
}

//zone is signed containing 10000 shards containing each 10 assertions
func BenchmarkSignZone10(b *testing.B) { benchmarkSignZone("test/zonefile100000", 10, b) }

//zone is signed containing 1000 shards containing each 100 assertions
func BenchmarkSignZone100(b *testing.B) { benchmarkSignZone("test/zonefile100000", 100, b) }

//zone is signed containing 100 shards containing each 1000 assertions
func BenchmarkSignZone1000(b *testing.B) { benchmarkSignZone("test/zonefile100000", 1000, b) }

func shardAssertions(assertions []*sections.AssertionSection, assertionsPerShard int) []sections.MessageSectionWithSigForward {
	var shards []sections.MessageSectionWithSigForward
	for i := 0; i < len(assertions); i++ {
		shard := &sections.ShardSection{
			Context:     assertions[i].Context,
			SubjectZone: assertions[i].SubjectZone,
			RangeFrom:   "aaaaa",
			RangeTo:     "zzzzz",
		}
		for i%assertionsPerShard != assertionsPerShard-1 && i < len(assertions)-1 {
			shard.Content = append(shard.Content, assertions[i])
			i++
		}
		shard.Content = append(shard.Content, assertions[i])
		shards = append(shards, shard)
	}
	return shards
}
