package util

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"

	"github.com/netsec-ethz/rains/internal/pkg/rainslib"
	"golang.org/x/crypto/ed25519"
)

//CreatePrivateKeysFile creates a file containing the json representation of two newly generated
//private keys with meta data information and stores them at the provided path
func CreatePrivateKeysFile(path string) error {
	_, privateKey, err := ed25519.GenerateKey(nil)
	_, privateKey2, err := ed25519.GenerateKey(nil)
	outputs := []rainslib.PrivateKey{
		rainslib.PrivateKey{rainslib.PublicKeyID{rainslib.Ed25519, rainslib.RainsKeySpace, 0}, hex.EncodeToString(privateKey)},
		rainslib.PrivateKey{rainslib.PublicKeyID{rainslib.Ed25519, rainslib.RainsKeySpace, 1}, hex.EncodeToString(privateKey2)},
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
