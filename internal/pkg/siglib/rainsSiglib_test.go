package siglib

import (
	"bytes"
	"io/ioutil"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/test/testdata"
	"golang.org/x/crypto/ed25519"
)

func TestSignAssertion(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := testdata.Assertion()
	if !SignSectionUnsafe(sec, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign assertion")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DeleteSig(0)
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignShard(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := testdata.Shard()
	if !SignSectionUnsafe(sec, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign shard")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DeleteSig(0)
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignPshard(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := testdata.Pshard()
	if !SignSectionUnsafe(sec, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign shard")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DeleteSig(0)
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignAddrAssertionIP4(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := testdata.AddrAssertionIP4()
	if !SignSectionUnsafe(sec, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign addr assertion")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DeleteSig(0)
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignAddrAssertionIP6(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := testdata.AddrAssertionIP6()
	if !SignSectionUnsafe(sec, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign addr assertion")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DeleteSig(0)
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignZone(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := testdata.Zone()
	if !SignSectionUnsafe(sec, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign zone")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DeleteSig(0)
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignQuery(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	msg := &message.Message{
		Token:        token.New(),
		Capabilities: []message.Capability{message.NoCapability, message.TLSOverTCP},
		Content:      []section.Section{testdata.Query()},
	}
	if !SignMessageUnsafe(msg, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign query")
		return
	}
	log.Info("Successful added sig", "sigLen", len(msg.Signatures))

	newSig := msg.Signatures[0]
	msg.Signatures = []signature.Sig{}
	encoding := new(bytes.Buffer)
	msg.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignAddrQuery(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	msg := &message.Message{
		Token:        token.New(),
		Capabilities: []message.Capability{message.NoCapability, message.TLSOverTCP},
		Content:      []section.Section{testdata.AddrQuery()},
	}
	if !SignMessageUnsafe(msg, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign addr query")
		return
	}
	log.Info("Successful added sig", "sigLen", len(msg.Signatures))

	newSig := msg.Signatures[0]
	msg.Signatures = []signature.Sig{}
	encoding := new(bytes.Buffer)
	msg.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignNotification(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	msg := &message.Message{
		Token:        token.New(),
		Capabilities: []message.Capability{message.NoCapability, message.TLSOverTCP},
		Content:      []section.Section{testdata.Notification(), testdata.NotificationNoData()},
	}
	if !SignMessageUnsafe(msg, genPrivateKey, testdata.Signature()) {
		t.Error("Was not able to sign query")
		return
	}
	log.Info("Successful added sig", "sigLen", len(msg.Signatures))

	newSig := msg.Signatures[0]
	msg.Signatures = []signature.Sig{}
	encoding := new(bytes.Buffer)
	msg.MarshalCBOR(cbor.NewWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

/*
func TestCheckSectionSignaturesErrors(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	maxVal := util.MaxCacheValidity{AddressAssertionValidity: time.Hour}
	keys0 := make(map[keys.PublicKeyID][]keys.PublicKey)
	keys1 := make(map[keys.PublicKeyID][]keys.PublicKey)
	keys1[keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}] = []keys.PublicKey{}
	var tests = []struct {
		input           section.WithSig
		inputPublicKeys map[keys.PublicKeyID][]keys.PublicKey
		want            bool
	}{
		{nil, nil, false},                                                                                                                               //msg nil
		{&section.Assertion{}, nil, false},                                                                                                              //pkeys nil
		{&section.Assertion{}, keys0, true},                                                                                                             //no signatures
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{}}, SubjectName: ":ip55:"}, keys0, false},                                         //checkStringField false
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{}}}, keys0, false},                                                                //no matching algotype in keys
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}}}}, keys1, true}, //sig expired
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
			ValidUntil: time.Now().Add(time.Second).Unix()}}}, keys1, false}, //VerifySignature invalid
	}
	for _, test := range tests {
		if CheckSectionSignatures(test.input, test.inputPublicKeys, maxVal) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, CheckSectionSignatures(test.input, test.inputPublicKeys, maxVal), test.input)
		}
	}
}


func TestCheckMessageSignaturesErrors(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(parser.Parser)
	message := data.GetMessage()
	message2 := data.GetMessage()
	message2.Capabilities = []message.Capability{message.Capability(":ip:")}
	message3 := data.GetMessage()
	message3.Signatures = []signature.Sig{signature.Sig{ValidUntil: time.Now().Add(time.Second).Unix()}}
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
	sections := data.GetMessage().Content
	_, pkey, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		input           section.MessageSectionWithSig
		inputPrivateKey interface{}
		inputSig        signature.Sig
		want            bool
	}{
		{nil, nil, signature.Sig{}, false},
		{
			sections[0].(section.MessageSectionWithSig),
			pkey,
			signature.Sig{
				PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
				ValidUntil:  time.Now().Add(time.Second).Unix(),
			},
			true,
		},
		{sections[0].(section.MessageSectionWithSig), pkey, signature.Sig{ValidUntil: time.Now().Unix() - 100}, false},
		{&section.AssertionSection{SubjectName: ":ip:"}, pkey, signature.Sig{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
		{sections[0].(section.MessageSectionWithSig), nil, signature.Sig{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
	}
	for _, test := range tests {
		if SignSection(test.input, test.inputPrivateKey, test.inputSig, encoder) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, SignSection(test.input, test.inputPrivateKey, test.inputSig, encoder), test.input)
		}
		if test.want && test.input.Sigs(keys.RainsKeySpace)[0].Data == nil {
			t.Error("msg.Sig does not contain generated signature data")
		}
	}
}

func TestSignMessage(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	encoder := new(parser.Parser)
	message := data.GetMessage()
	_, pkey, _ := ed25519.GenerateKey(nil)
	var tests = []struct {
		input           *message.RainsMessage
		inputPrivateKey interface{}
		inputSig        signature.Sig
		want            bool
	}{
		{nil, nil, signature.Sig{}, false},
		{
			&message,
			pkey,
			signature.Sig{
				PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
				ValidUntil:  time.Now().Add(time.Second).Unix(),
			},
			true,
		},
		{&message, pkey, signature.Sig{ValidUntil: time.Now().Add(time.Second).Unix() - 100}, false},
		{&message.RainsMessage{Capabilities: []message.Capability{message.Capability(":ip:")}}, pkey,
			signature.Sig{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
		{&message.RainsMessage{}, nil, signature.Sig{ValidUntil: time.Now().Add(time.Second).Unix()}, false},
	}
	for _, test := range tests {
		if SignMessage(test.input, test.inputPrivateKey, test.inputSig, encoder) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, SignMessage(test.input, test.inputPrivateKey, test.inputSig, encoder), test.input)
		}
		if test.want && test.input.Signatures[0].Data == nil {
			t.Error("msg.Sig does not contain generated signature data")
		}
	}
}

func TestCheckMessageStringFields(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	message := data.GetMessage()
	var tests = []struct {
		input *message.RainsMessage
		want  bool
	}{
		{nil, false},
		{&message, true},
		{&message.RainsMessage{Capabilities: []message.Capability{message.Capability(":ip:")}}, false},
		{&message.RainsMessage{Content: []section.Section{&section.Assertion{SubjectName: ":ip:"}}}, false},
	}
	for _, test := range tests {
		if checkMessageStringFields(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkMessageStringFields(test.input), test.input)
		}
	}
}

func TestCheckStringFields(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	sections := data.GetMessage().Content
	var tests = []struct {
		input section.MessageSection
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
		{&section.AssertionSection{SubjectName: ":ip:"}, false},
		{&section.AssertionSection{Context: ":ip:"}, false},
		{&section.AssertionSection{SubjectZone: ":ip:"}, false},
		{&section.AssertionSection{Content: []object.Object{object.Object{Type: object.OTRegistrar, Value: ":ip55:"}}}, false},
		{&section.ShardSection{Context: ":ip:"}, false},
		{&section.ShardSection{SubjectZone: ":ip:"}, false},
		{&section.ShardSection{RangeFrom: ":ip:"}, false},
		{&section.ShardSection{RangeTo: ":ip:"}, false},
		{&section.ShardSection{Content: []*section.AssertionSection{&section.AssertionSection{SubjectName: ":ip:"}}}, false},
		{&section.ZoneSection{SubjectZone: ":ip:"}, false},
		{&section.ZoneSection{Context: ":ip:"}, false},
		{&section.ZoneSection{Content: []section.MessageSectionWithSigForward{&section.AssertionSection{SubjectName: ":ip:"}}}, false},
		{&query.QuerySection{Context: ":ip:"}, false},
		{&query.QuerySection{Name: ":ip:"}, false},
		{&section.NotificationSection{Data: ":ip:"}, false},
		{&section.AddressQuerySection{Context: ":ip:"}, false},
		{&section.AddressAssertionSection{Context: ":ip:"}, false},
		{&section.AddressAssertionSection{Content: []object.Object{object.Object{Type: object.OTRegistrant, Value: ":ip55:"}}}, false},
		{&section.AddressZoneSection{Context: ":ip:"}, false},
		{&section.AddressZoneSection{Content: []*section.AddressAssertionSection{&section.AddressAssertionSection{Context: ":ip:"}}}, false},
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
		{[]object.Object{object.Object{Type: object.OTName, Value: object.Name{Name: ":ip55:"}}}, false},
		{[]object.Object{object.Object{Type: object.OTRedirection, Value: ":ip55:"}}, false},
		{[]object.Object{object.Object{Type: object.OTNameset, Value: object.NamesetExpr(":ip55:")}}, false},
		{[]object.Object{object.Object{Type: object.OTServiceInfo, Value: object.ServiceInfo{Name: ":ip55:"}}}, false},
		{[]object.Object{object.Object{Type: object.OTRegistrar, Value: ":ip55:"}}, false},
		{[]object.Object{object.Object{Type: object.OTRegistrant, Value: ":ip55:"}}, false},
		{[]object.Object{object.Object{Type: object.Type(-1), Value: nil}}, false},
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
*/
var result bool

//Reads a zonefile and signs all contained assertions
func benchmarkSignAssertions(zonefileName string, b *testing.B) {
	log.Root().SetHandler(log.DiscardHandler())

	parser := new(zonefile.Parser)
	data, err := ioutil.ReadFile(zonefileName)
	if err != nil {
		log.Error("Was not able to read zonefile", "error", err)
		return
	}
	zone, err := parser.DecodeZone(data)
	if err != nil {
		log.Error("Was not able to decode zonefile", "error", err)
		return
	}
	_, pkey, _ := ed25519.GenerateKey(nil)
	sig := signature.Sig{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		for _, sec := range zone.Content {
			result = SignSectionUnsafe(sec, pkey, sig)
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
	parser := new(zonefile.Parser)
	data, err := ioutil.ReadFile(zonefileName)
	if err != nil {
		log.Error("Was not able to read zonefile", "error", err)
		return
	}
	zone, err := parser.DecodeZone(data)
	if err != nil {
		log.Error("Was not able to decode zonefile", "error", err)
		return
	}
	shards := shardAssertions(zone.Content, assertionsPerShard)
	_, pkey, _ := ed25519.GenerateKey(nil)
	sig := signature.Sig{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		for _, shard := range shards {
			result = SignSectionUnsafe(shard, pkey, sig)
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
	parser := new(zonefile.Parser)
	data, err := ioutil.ReadFile(zonefileName)
	if err != nil {
		log.Error("Was not able to read zonefile", "error", err)
		return
	}
	zone, err := parser.DecodeZone(data)
	if err != nil {
		log.Error("Was not able to decode zonefile", "error", err)
		return
	}
	shards := shardAssertions(zone.Content, assertionsPerShard)
	newZone := &section.Zone{
		Context:     zone.Context,
		SubjectZone: zone.SubjectZone,
		Content:     shards,
	}
	_, pkey, _ := ed25519.GenerateKey(nil)
	sig := signature.Sig{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
		ValidUntil:  time.Now().Add(time.Hour).Unix(),
	}
	for n := 0; n < b.N; n++ {
		result = SignSectionUnsafe(newZone, pkey, sig)
	}
}

//zone is signed containing 10000 shards containing each 10 assertions
func BenchmarkSignZone10(b *testing.B) { benchmarkSignZone("test/zonefile100000", 10, b) }

//zone is signed containing 1000 shards containing each 100 assertions
func BenchmarkSignZone100(b *testing.B) { benchmarkSignZone("test/zonefile100000", 100, b) }

//zone is signed containing 100 shards containing each 1000 assertions
func BenchmarkSignZone1000(b *testing.B) { benchmarkSignZone("test/zonefile100000", 1000, b) }

func shardAssertions(sections []section.WithSigForward, assertionsPerShard int) []section.WithSigForward {
	var shards []section.WithSigForward
	for i := 0; i < len(sections); i++ {
		assertion := sections[i].(*section.Assertion)
		shard := &section.Shard{
			Context:     assertion.Context,
			SubjectZone: assertion.SubjectZone,
			RangeFrom:   "aaaaa",
			RangeTo:     "zzzzz",
		}
		for i%assertionsPerShard != assertionsPerShard-1 && i < len(sections)-1 {
			shard.Content = append(shard.Content, assertion)
			i++
		}
		shard.Content = append(shard.Content, assertion)
		shards = append(shards, shard)
	}
	return shards
}
