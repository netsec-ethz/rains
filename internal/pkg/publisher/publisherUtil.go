package publisher

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

//LoadConfig loads configuration information from configPath
func LoadConfig(configPath string) (Config, error) {
	var config Config
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error("Could not open config file...", "path", configPath, "error", err)
		return Config{}, err
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Error("Could not unmarshal json format of config", "error", err)
		return Config{}, err
	}
	config.MetaDataConf.SigSigningInterval *= time.Second
	return config, nil
}

//LoadPrivateKeys reads private keys from the path provided in the config and returns a map from
//PublicKeyID to the corresponding private key data.
func LoadPrivateKeys(path string) (map[keys.PublicKeyID]interface{}, error) {
	var privateKeys []keys.PrivateKey
	file, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Could not open config file...", "path", path, "error", err)
		return nil, err
	}
	if err = json.Unmarshal(file, &privateKeys); err != nil {
		log.Error("Could not unmarshal json format of private keys", "error", err)
		return nil, err
	}
	output := make(map[keys.PublicKeyID]interface{})
	for _, keyData := range privateKeys {
		keyString := keyData.Key.(string)
		privateKey := make([]byte, hex.DecodedLen(len([]byte(keyString))))
		privateKey, err := hex.DecodeString(keyString)
		if err != nil {
			log.Error("Was not able to decode privateKey", "error", err)
			return nil, err
		}
		if len(privateKey) != ed25519.PrivateKeySize {
			log.Error("Private key length is incorrect", "expected", ed25519.PrivateKeySize,
				"actual", len(privateKey))
			return nil, errors.New("incorrect private key length")
		}
		output[keyData.PublicKeyID] = ed25519.PrivateKey(privateKey)
	}
	return output, nil
}

func StorePrivateKey(path string, privateKeys []keys.PrivateKey) error {
	for i, key := range privateKeys {
		privateKeys[i].Key = hex.EncodeToString(key.Key.(ed25519.PrivateKey))
	}
	if encoding, err := json.Marshal(privateKeys); err != nil {
		return err
	} else {
		return ioutil.WriteFile(path, encoding, 0600)
	}
}
