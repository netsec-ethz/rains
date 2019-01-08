package siglib

import (
	"bytes"
	"testing"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"golang.org/x/crypto/ed25519"
)

func TestSignAssertion(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := section.GetAssertion()
	if !SignSectionUnsafe(sec, genPrivateKey, section.Signature()) {
		t.Error("Was not able to sign assertion")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DontAddSigInMarshaller()
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewCBORWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignShard(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := section.GetShard()
	if !SignSectionUnsafe(sec, genPrivateKey, section.Signature()) {
		t.Error("Was not able to sign shard")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DontAddSigInMarshaller()
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewCBORWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignPshard(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := section.GetPshard()
	if !SignSectionUnsafe(sec, genPrivateKey, section.Signature()) {
		t.Error("Was not able to sign shard")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DontAddSigInMarshaller()
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewCBORWriter(encoding))

	//Test signature
	if !newSig.VerifySignature(genPublicKey, encoding.Bytes()) {
		t.Error("Sig does not match")
	}
}

func TestSignZone(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := section.GetZone()
	if !SignSectionUnsafe(sec, genPrivateKey, section.Signature()) {
		t.Error("Was not able to sign zone")
		return
	}
	log.Info("Successful added sig", "sigLen", len(sec.AllSigs()))

	newSig := sec.AllSigs()[0]
	sec.DontAddSigInMarshaller()
	encoding := new(bytes.Buffer)
	sec.MarshalCBOR(cbor.NewCBORWriter(encoding))

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
		Content:      []section.Section{section.GetQuery()},
	}
	if !SignMessageUnsafe(msg, genPrivateKey, section.Signature()) {
		t.Error("Was not able to sign query")
		return
	}
	log.Info("Successful added sig", "sigLen", len(msg.Signatures))

	newSig := msg.Signatures[0]
	msg.Signatures = []signature.Sig{}
	encoding := new(bytes.Buffer)
	msg.MarshalCBOR(cbor.NewCBORWriter(encoding))

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
		Content:      []section.Section{section.GetNotification(), section.NotificationNoData()},
	}
	if !SignMessageUnsafe(msg, genPrivateKey, section.Signature()) {
		t.Error("Was not able to sign query")
		return
	}
	log.Info("Successful added sig", "sigLen", len(msg.Signatures))

	newSig := msg.Signatures[0]
	msg.Signatures = []signature.Sig{}
	encoding := new(bytes.Buffer)
	msg.MarshalCBOR(cbor.NewCBORWriter(encoding))

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
	message := section.GetGetMessage()
	message2 := section.GetGetMessage()
	message2.Capabilities = []message.Capability{message.Capability(":ip:")}
	message3 := section.GetGetMessage()
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
	sections := section.GetGetMessage().Content
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
	message := section.GetGetMessage()
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
	message := section.GetGetMessage()
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
	sections := section.GetGetMessage().Content
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
