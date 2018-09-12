package rainspub

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainslib"
	"golang.org/x/crypto/ed25519"
)

//loadZonefile loads the zonefile from disk.
func loadZonefile() (*rainslib.ZoneSection, error) {
	file, err := ioutil.ReadFile(config.ZonefilePath)
	if err != nil {
		log.Error("Was not able to read zone file", "path", config.ZonefilePath)
		return nil, err
	}
	//FIXME CFE replace with call to yacc generated zonefile parser.
	zone, err := parser.DecodeZone(file)
	if err != nil {
		log.Error("Was not able to parse zone file.", "error", err)
		return nil, err
	}
	return zone, nil
}

//loadPrivateKeys reads private keys from the path provided in the config and returns a map from
//PublicKeyID to the corresponding private key data.
func loadPrivateKeys() (map[rainslib.PublicKeyID]interface{}, error) {
	var privateKeys []rainslib.PrivateKey
	file, err := ioutil.ReadFile(config.PrivateKeyPath)
	if err != nil {
		log.Error("Could not open config file...", "path", config.PrivateKeyPath, "error", err)
		return nil, err
	}
	if err = json.Unmarshal(file, &privateKeys); err != nil {
		log.Error("Could not unmarshal json format of private keys", "error", err)
		return nil, err
	}
	output := make(map[rainslib.PublicKeyID]interface{})
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
		output[keyData.PublicKeyID] = privateKey
	}
	return output, nil
}
