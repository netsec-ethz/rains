package rainsMsgParser

import (
	"math/rand"
	"rains/rainslib"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

func TestSigningProcess(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	if err != nil {
		t.Error(err)
	}
	a := rainslib.AssertionSection{Context: ".", SubjectZone: "ch", SubjectName: "ethz", Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}}}
	sec := a.CreateStub()
	p := RainsMsgParser{}
	aByte, err := p.RevParseSignedMsgSection(sec)
	if err != nil {
		t.Error(err)
	}
	sig := rainslib.SignData(rainslib.Ed25519, privateKey, []byte(aByte))
	ok := rainslib.VerifySignature(rainslib.Ed25519, publicKey, []byte(aByte), sig)
	if !ok {
		t.Error("Signature did not verify")
	}
}
