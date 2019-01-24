package siglib

import (
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

/*func TestSignAssertion(t *testing.T) {
	genPublicKey, genPrivateKey, _ := ed25519.GenerateKey(nil)
	sec := section.GetAssertion()
	if err := SignSectionUnsafe(sec, genPrivateKey, section.Signature()); err != nil {
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

func TestSignErrors(t *testing.T) {
	var tests = []struct {
		section section.WithSig
		sig     signature.Sig
		key     interface{}
	}{
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{}}}, signature.Sig{}, nil},
		{&section.Assertion{}, signature.Sig{Data: []byte("some data")}, nil},
	}
	for i, test := range tests {
		ok := SignSectionUnsafe(test.section, test.key, test.sig)
		if ok {
			t.Fatalf("%d: SignSectionUnsafe should fail", i)
		}
	}
}*/

func TestCheckSectionSignaturesErrors(t *testing.T) {
	keys0 := make(map[keys.PublicKeyID][]keys.PublicKey)
	keys1 := make(map[keys.PublicKeyID][]keys.PublicKey)
	keys1[keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}] = []keys.PublicKey{
		keys.PublicKey{ValidSince: time.Now().Unix(), ValidUntil: time.Now().Add(time.Minute).Unix()}}
	keys2 := make(map[keys.PublicKeyID][]keys.PublicKey)
	keys2[keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}] = []keys.PublicKey{}
	var tests = []struct {
		input           section.WithSig
		inputPublicKeys map[keys.PublicKeyID][]keys.PublicKey
		want            bool
	}{
		{nil, nil, false},                                                                                                                                //msg nil
		{&section.Assertion{}, nil, false},                                                                                                               //pkeys nil
		{&section.Assertion{}, keys0, true},                                                                                                              //no signatures
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{}}, SubjectName: ":ip55:"}, keys0, false},                                          //checkStringField false
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{}}}, keys0, false},                                                                 //no matching algotype in keys
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519}}}}, keys1, false}, //sig expired
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
			ValidUntil: time.Now().Add(time.Minute).Unix()}}}, keys2, false}, //public key not overlapping
		{&section.Assertion{Signatures: []signature.Sig{signature.Sig{PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519},
			ValidUntil: time.Now().Add(time.Minute).Unix()}}}, keys1, false}, //VerifySignature invalid
	}
	for _, test := range tests {
		res := checkSectionSignatures(test.input, test.inputPublicKeys, util.MaxCacheValidity{})
		if res != test.want {
			t.Fatalf("expected=%v, actual=%v, value=%v", test.want, res, test.input)
		}
	}
}

func TestCheckMessageStringFields(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	msg := message.GetMessage()
	var tests = []struct {
		input *message.Message
		want  bool
	}{
		{nil, false},
		{&msg, true},
		{&message.Message{Capabilities: []message.Capability{message.Capability(":ip:")}}, false},
		{&message.Message{Content: []section.Section{&section.Assertion{SubjectName: ":ip:"}}}, false},
	}
	for _, test := range tests {
		if checkMessageStringFields(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkMessageStringFields(test.input), test.input)
		}
	}
}

func TestCheckStringFields(t *testing.T) {
	sections := message.GetMessage().Content
	var tests = []struct {
		input section.Section
		want  bool
	}{
		{nil, false},
		{sections[0], true},
		{sections[1], true},
		{sections[2], true},
		{sections[3], true},
		{sections[4], true},
		{sections[5], true},
		{&section.Assertion{SubjectName: ":ip:"}, false},
		{&section.Assertion{Context: ":ip:"}, false},
		{&section.Assertion{SubjectZone: ":ip:"}, false},
		{&section.Assertion{Content: []object.Object{object.Object{Type: object.OTRegistrar, Value: ":ip55:"}}}, false},
		{&section.Pshard{RangeFrom: ":ip:"}, false},
		{&section.Pshard{RangeTo: ":ip:"}, false},
		{&section.Shard{Context: ":ip:"}, false},
		{&section.Shard{SubjectZone: ":ip:"}, false},
		{&section.Shard{RangeFrom: ":ip:"}, false},
		{&section.Shard{RangeTo: ":ip:"}, false},
		{&section.Shard{Content: []*section.Assertion{&section.Assertion{SubjectName: ":ip:"}}}, false},
		{&section.Zone{SubjectZone: ":ip:"}, false},
		{&section.Zone{Context: ":ip:"}, false},
		{&section.Zone{Content: []*section.Assertion{&section.Assertion{SubjectName: ":ip:"}}}, false},
		{&query.Name{Context: ":ip:"}, false},
		{&query.Name{Name: ":ip:"}, false},
		{&section.Notification{Data: ":ip:"}, false},
	}
	for _, test := range tests {
		val := CheckStringFields(test.input)
		if val != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, val, test.input)
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
		{object.AllObjects(), true},
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
		if checkCapabilities(test.input) != test.want {
			t.Errorf("expected=%v, actual=%v, value=%v", test.want, checkCapabilities(test.input), test.input)
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

func TestValidSectionAndSignature(t *testing.T) {
	var tests = []struct {
		s        section.WithSig
		sig      signature.Sig
		expected bool
	}{
		{nil, signature.Sig{}, false},
		{&section.Assertion{}, signature.Sig{}, false},
		{&section.Assertion{}, signature.Sig{}, false},
		{&section.Shard{RangeFrom: ":A:"}, signature.Sig{ValidUntil: time.Now().Add(time.Minute).Unix()}, false},
		{&section.Assertion{}, signature.Sig{ValidUntil: time.Now().Add(time.Minute).Unix()}, true},
	}
	for i, test := range tests {
		if test.s != nil {
			test.s.AddSig(test.sig)
		}
		ok := ValidSectionAndSignature(test.s)
		if ok != test.expected {
			t.Fatalf("%d: unexpected result. expected=%v actual=%v", i, test.expected, ok)
		}
	}
}

func TestCheckSignatureNotExpired(t *testing.T) {
	var tests = []struct {
		s        section.WithSig
		sig      signature.Sig
		expected bool
	}{
		{nil, signature.Sig{}, true},
		{&section.Assertion{}, signature.Sig{}, false},
		{&section.Assertion{}, signature.Sig{ValidUntil: time.Now().Add(time.Minute).Unix()}, true},
	}
	for i, test := range tests {
		if test.s != nil {
			test.s.AddSig(test.sig)
		}
		ok := CheckSignatureNotExpired(test.s)
		if ok != test.expected {
			t.Fatalf("%d: unexpected result. expected=%v actual=%v", i, test.expected, ok)
		}
	}
}
