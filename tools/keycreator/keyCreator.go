package keycreator

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
	DelegationAssertion(".", ".")
}

//DelegationAssertion generates a new public/private key pair for the given context and zone. It stores the private key and a delegation assertion to a file.
//In case of root public key the assertion is self signed (zone=.)
func DelegationAssertion(context, zone string) error {
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
		if ok := addSignature(assertion, privateKey, pkey.PublicKeyID); !ok {
			return errors.New("Was not able to sign the assertion")
		}
	}
	var keyPath string
	//Store root zone file
	if zone == "." {
		err = util.Save("keys/selfSignedRootDelegationAssertion.gob", assertion)
		keyPath = "keys/rootPrivateKey.txt"
	} else {
		err = util.Save("keys/delegationAssertion.gob", assertion)
		keyPath = "keys/privateKey.txt"
	}
	if err != nil {
		log.Error("Was not able to encode the assertion", "assertion", assertion)
		return err
	}
	return writePrivateKeys(keyPath, []keys.PrivateKey{
		keys.PrivateKey{PublicKeyID: pkey.PublicKeyID, Key: hex.EncodeToString(privateKey)},
	})
}

//addSignature signs the section with the public key and adds the resulting signature to the section
func addSignature(a section.WithSig, key ed25519.PrivateKey, publicKeyID keys.PublicKeyID) bool {
	sig := signature.Sig{
		PublicKeyID: publicKeyID,
		ValidSince:  time.Now().Unix(),
		ValidUntil:  time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	return siglib.SignSection(a, key, sig)
}

//storeKeyPair stores the public and private key to temp/private.key (hex
//encoded). The public key is the second half of the private key's byte string.
func storeKeyPair(privateKey ed25519.PrivateKey) error {
	if _, err := os.Stat("tmp"); os.IsNotExist(err) {
		os.Mkdir("tmp", 0775)
	}
	privateKeyEnc := make([]byte, hex.EncodedLen(len(privateKey)))
	hex.Encode(privateKeyEnc, privateKey)
	err := ioutil.WriteFile("tmp/private.key", privateKeyEnc, 0600)
	if err != nil {
		return err
	}
	return nil
}

//SignDelegation signs the delegation stored at delegationPath with the private key stored at privateKeyPath
func SignDelegation(delegationPath, privateKeyPath string) error {
	/*privateKey, err := ioutil.ReadFile(privateKeyPath)
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
	}*/
	return errors.New("Not yet implemented")
}

//CreatePublisherPrivateKeysFile creates a file containing the json representation of two newly
//generated private keys with meta data information and stores them at the provided path
func CreatePublisherPrivateKeysFile(path string) error {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	_, privateKey2, _ := ed25519.GenerateKey(nil)
	outputs := []keys.PrivateKey{
		keys.PrivateKey{keys.PublicKeyID{algorithmTypes.Ed25519, keys.RainsKeySpace, 0}, hex.EncodeToString(privateKey)},
		keys.PrivateKey{keys.PublicKeyID{algorithmTypes.Ed25519, keys.RainsKeySpace, 1}, hex.EncodeToString(privateKey2)},
	}
	return writePrivateKeys(path, outputs)
}

func writePrivateKeys(path string, keys []keys.PrivateKey) error {
	jsonOutput, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, jsonOutput, 0600)
	if err != nil {
		return err
	}
	return nil
}
