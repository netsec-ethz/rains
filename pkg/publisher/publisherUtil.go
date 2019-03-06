package publisher

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
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
	output := make(map[keys.PublicKeyID]interface{})
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("Was not able to read directory: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), keyManager.SecSuffix) {
			keyPem, err := keyManager.DecryptKey(path, f.Name(), "")
			if err != nil {
				return nil, fmt.Errorf("Was not able to decrypt key: %v", err)
			}
			keyID, pkey, err := keyManager.PemToKeyID(keyPem)
			if err != nil {
				return nil, fmt.Errorf("Was not able to decode pem encoded private key: %v", err)
			}
			if _, ok := output[keyID]; ok {
				return nil, errors.New("Two keys for the same key meta data are not allowed")
			}
			output[keyID] = pkey
		}
	}
	return output, nil
}
