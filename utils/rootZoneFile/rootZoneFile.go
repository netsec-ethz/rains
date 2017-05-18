package rootZoneFile

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"rains/rainslib"
	"rains/utils/parser"
	"time"

	"golang.org/x/crypto/ed25519"
)

func CreateRootZoneFile() error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	if err != nil {
		return err
	}
	assertion := &rainslib.AssertionSection{
		Context:     ".",
		SubjectZone: "ethz.ch",
		SubjectName: "@",
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}},
	}
	err = addSignature(assertion, privateKey)
	if err != nil {
		return err
	}
	rootZoneFile := fmt.Sprintf(":Z: . . [ :A: @ [ :deleg: 1 %s ] ]", publicKey)
	//Store private key
	if _, err := os.Stat("tmp"); os.IsNotExist(err) {
		os.Mkdir("tmp", 0775)
	}
	err = ioutil.WriteFile("tmp/privateKey.txt", []byte(privateKey), 0644)
	if err != nil {
		return err
	}
	//Store root zone file
	err = ioutil.WriteFile("tmp/rootZoneFile.txt", []byte(rootZoneFile), 0644)
	if err != nil {
		return err
	}
	return nil
}

func addSignature(a *rainslib.AssertionSection, key ed25519.PrivateKey) error {
	msgParser := parser.RainsMsgParser{}
	data, err := msgParser.RevParseSignedMsgSection(rainslib.MessageSectionWithSig(a))
	if err != nil {
		return err
	}
	sigData := rainslib.SignData(rainslib.Ed25519, key, []byte(data))
	signature := rainslib.Signature{
		Algorithm:  rainslib.Ed25519,
		KeySpace:   rainslib.RainsKeySpace,
		Data:       sigData,
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	a.Signatures = append(a.Signatures, signature)
	return nil
}
