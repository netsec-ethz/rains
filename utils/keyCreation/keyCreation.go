package keyCreation

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"time"

	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//CreateDelegationAssertion generates a new public/private key pair for the given context and zone. It stores the private key and a delegation assertion to a file.
//In case of root public key the assertion is self signed (zone=.)
func CreateDelegationAssertion(context, zone string) error {
	//FIXME CFE change source of randomness
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	log.Debug("Generated root public Key", "publicKey", publicKey)
	pkey := rainslib.PublicKey{
		PublicKeyID: rainslib.PublicKeyID{
			KeySpace:  rainslib.RainsKeySpace,
			Algorithm: rainslib.Ed25519,
		},
		Key:        publicKey,
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	assertion := &rainslib.AssertionSection{
		Context:     context,
		SubjectZone: zone,
		SubjectName: "@",
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTDelegation, Value: pkey}},
	}
	if zone == "." {
		if ok := addSignature(assertion, privateKey); !ok {
			return errors.New("Was not able to sign the assertion")
		}
	}
	if err := storeKeyPair(publicKey, privateKey); err != nil {
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

//addSignature signs the section with the public key and adds the resulting signature to the section
func addSignature(a rainslib.MessageSectionWithSig, key ed25519.PrivateKey) bool {
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: rainslib.Ed25519,
			KeySpace:  rainslib.RainsKeySpace,
		},
		//FIXME CFE add validity times to config
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	return rainsSiglib.SignSection(a, key, signature, zoneFileParser.Parser{})
}

//storeKeyPair stores the public and private key to separate files (hex encoded)
func storeKeyPair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) error {
	if _, err := os.Stat("tmp"); os.IsNotExist(err) {
		os.Mkdir("tmp", 0775)
	}
	privateKeyEnc := make([]byte, hex.EncodedLen(len(privateKey)))
	hex.Encode(privateKeyEnc, privateKey)
	err := ioutil.WriteFile("tmp/private.key", privateKeyEnc, 0600)
	if err != nil {
		return err
	}
	publicKeyEnc := make([]byte, hex.EncodedLen(len(publicKey)))
	hex.Encode(publicKeyEnc, publicKey)
	err = ioutil.WriteFile("tmp/public.key", publicKeyEnc, 0600)
	return err
}

//SignDelegation signs the delegation stored at delegationPath with the private key stored at privateKeyPath
func SignDelegation(delegationPath, privateKeyPath string) error {
	privateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	delegation := &rainslib.AssertionSection{}
	err = rainslib.Load(delegationPath, delegation)
	if err != nil {
		return err
	}
	if ok := addSignature(delegation, privateKey); !ok {
		return errors.New("Was not able to sign and add signature")
	}
	err = rainslib.Save(delegationPath, delegation)
	if err != nil {
		log.Error("Was not able to encode and store the delegation", "delegation", delegation, "error", err)
	}
	return err
}

//CreateEd25519Keypair creates a ed25519 keypair where it stores the keys hexadecimal encoded to privateKeyPath or publicKeyPath respectively
func CreateEd25519Keypair(privateKeyPath, publicKeyPath string) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Error("Could not generate key pair", "error", err)
		return
	}
	err = ioutil.WriteFile(privateKeyPath, []byte(hex.EncodeToString(privateKey)), 0644)
	if err != nil {
		log.Error("Could not store the private key", "path", privateKeyPath, "error", err)
	}
	err = ioutil.WriteFile(publicKeyPath, []byte(hex.EncodeToString(publicKey)), 0644)
	if err != nil {
		log.Error("Could not store the public key", "path", publicKeyPath, "error", err)
	}
}
