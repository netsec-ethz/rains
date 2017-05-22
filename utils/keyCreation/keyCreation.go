package keyCreation

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

//CreateDelegationAssertion generates a new public/private key pair for the given context and zone. It stores the private key and a delegation assertion to a file.
//In case of root public key the assertion is self signed (zone=.)
func CreateDelegationAssertion(context, zone string) error {
	//FIXME CFE change source of randomness
	publicKey, privateKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	if err != nil {
		return err
	}
	log.Debug("Generated root public Key", "publicKey", publicKey)
	assertion := &rainslib.AssertionSection{
		Context:     context,
		SubjectZone: zone,
		SubjectName: "@",
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}},
	}
	msgParser := parser.RainsMsgParser{}
	if zone == "." {
		err = addSignature(assertion, privateKey, msgParser)
	}
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
	if zone == "." {
		err = rainslib.Save("tmp/selfSignedRootDelegationAssertion.gob", assertion)
	} else {
		err = rainslib.Save("tmp/delegationAssertion.gob", assertion)
	}
	if err != nil {
		log.Error("Was not able to encode the assertion", "assertion", assertion)
	}
	return err
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
