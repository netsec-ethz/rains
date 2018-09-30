package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"golang.org/x/crypto/ed25519"
)

func main() {
	CreatePublisherPrivateKeysFile("pubPrivateKeys.txt")
	CreateDelegationAssertion(".", ".")
}

//CreateDelegationAssertion generates a new public/private key pair for the given context and zone. It stores the private key and a delegation assertion to a file.
//In case of root public key the assertion is self signed (zone=.)
func CreateDelegationAssertion(context, zone string) error {
	//FIXME CFE change source of randomness
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	pkey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			KeyPhase:  0,
			Algorithm: algorithmTypes.Ed25519,
		},
		Key:        publicKey,
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	assertion := &section.Assertion{
		Context:     context,
		SubjectZone: zone,
		SubjectName: "@",
		Content:     []object.Object{object.Object{Type: object.OTDelegation, Value: pkey}},
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
		err = util.Save("selfSignedRootDelegationAssertion.gob", assertion)
	} else {
		err = util.Save("delegationAssertion.gob", assertion)
	}
	if err != nil {
		log.Error("Was not able to encode the assertion", "assertion", assertion)
	}
	return err
}

//addSignature signs the section with the public key and adds the resulting signature to the section
func addSignature(a section.WithSig, key ed25519.PrivateKey) bool {
	sig := signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			Algorithm: algorithmTypes.Ed25519,
			KeyPhase:  0,
			KeySpace:  keys.RainsKeySpace,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	return siglib.SignSection(a, key, sig)
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
	delegation := &section.Assertion{}
	err = util.Load(delegationPath, delegation)
	if err != nil {
		return err
	}
	if ok := addSignature(delegation, privateKey); !ok {
		return errors.New("Was not able to sign and add signature")
	}
	err = util.Save(delegationPath, delegation)
	if err != nil {
		log.Error("Was not able to encode and store the delegation", "delegation", delegation, "error", err)
	}
	return err
}

//CreatePublisherPrivateKeysFile creates a file containing the json representation of two newly
//generated private keys with meta data information and stores them at the provided path
func CreatePublisherPrivateKeysFile(path string) error {
	_, privateKey, err := ed25519.GenerateKey(nil)
	_, privateKey2, err := ed25519.GenerateKey(nil)
	outputs := []keys.PrivateKey{
		keys.PrivateKey{keys.PublicKeyID{algorithmTypes.Ed25519, keys.RainsKeySpace, 0}, hex.EncodeToString(privateKey)},
		keys.PrivateKey{keys.PublicKeyID{algorithmTypes.Ed25519, keys.RainsKeySpace, 1}, hex.EncodeToString(privateKey2)},
	}
	jsonOutput, err := json.Marshal(outputs)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, jsonOutput, 0600)
	if err != nil {
		return err
	}
	return nil
}