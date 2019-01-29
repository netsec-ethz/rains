package keycreator

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"path"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/keyManager"

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

func GenerateRootKey(publicKeyPath, privateKeyPath string, phase int) error {
	folder, file := path.Split(privateKeyPath)
	err := keyManager.GenerateKey(folder, file, "", algorithmTypes.Ed25519.String(), "", phase)
	if err != nil {
		return err
	}

}

//DelegationAssertion generates a new public/private key pair for the given context and zone. It stores the private key and a delegation assertion to a file.
//In case of root public key the assertion is self signed (zone=.)
func DelegationAssertion(context, zone, rootPath, keyPath string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	pkey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			KeyPhase:  1,
			Algorithm: algorithmTypes.Ed25519,
		},
		Key: publicKey,
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
	//Store root zone file
	if zone == "." {
		err = util.Save(rootPath, assertion)
	} else {
		err = util.Save(rootPath, assertion)
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
	a.AddSig(sig)
	ks := map[keys.PublicKeyID]interface{}{publicKeyID: key}
	return siglib.SignSectionUnsafe(a, ks) == nil
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
