package rootZoneFile

import (
	"io/ioutil"
	"math/rand"
	"os"
	"rains/rainslib"
	"rains/utils/parser"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func CreateRootZoneFile() error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	if err != nil {
		return err
	}
	assertion := &rainslib.AssertionSection{
		Context:     ".",
		SubjectZone: ".",
		SubjectName: "@",
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}},
	}
	msgParser := parser.RainsMsgParser{}
	err = addSignature(assertion, privateKey, msgParser)
	if err != nil {
		return err
	}
	//Store private key
	if _, err := os.Stat("tmp"); os.IsNotExist(err) {
		os.Mkdir("tmp", 0775)
	}
	err = ioutil.WriteFile("tmp/private.Key", []byte(privateKey), 0644)
	if err != nil {
		return err
	}
	//Store root zone file
	//FIXME CFE is there a better format than .txt?
	a, err := msgParser.RevParseSignedMsgSection(assertion)
	if err != nil {
		log.Error("Could not change the assertion to its string representation")
		return err
	}
	err = ioutil.WriteFile("tmp/rootZoneFile.txt", []byte(a), 0644)
	if err != nil {
		return err
	}
	return nil
}

func addSignature(a rainslib.MessageSectionWithSig, key ed25519.PrivateKey, msgParser parser.RainsMsgParser) error {
	data, err := msgParser.RevParseSignedMsgSection(a)
	if err != nil {
		return err
	}
	sigData := rainslib.SignData(rainslib.Ed25519, key, []byte(data))
	signature := rainslib.Signature{
		Algorithm: rainslib.Ed25519,
		KeySpace:  rainslib.RainsKeySpace,
		Data:      sigData,
		//FIXME CFE add validity times to config
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	a.AddSig(signature)
	return nil
}
