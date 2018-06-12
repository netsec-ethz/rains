package rainspub

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"time"

	log "github.com/inconshreveable/log15"

	"golang.org/x/crypto/ed25519"
)

//loadConfig loads configuration information from configPath
func loadConfig(configPath string) error {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error("Could not open config file...", "path", configPath, "error", err)
		return err
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Error("Could not unmarshal json format of config", "error", err)
		return err
	}
	config.AssertionValidSince *= time.Hour
	config.ShardValidSince *= time.Hour
	config.ZoneValidSince *= time.Hour
	config.DelegationValidSince *= time.Hour
	config.AssertionValidUntil *= time.Hour
	config.ShardValidUntil *= time.Hour
	config.ZoneValidUntil *= time.Hour
	config.DelegationValidUntil *= time.Hour
	return nil
}

//loadPrivateKey loads the zone private key
//TODO CFE remove when we have air gapping
func loadPrivateKey(privateKeyPath string) error {
	privKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Error("Was not able to read privateKey", "path", privateKeyPath, "error", err)
		return err
	}
	zonePrivateKey = make([]byte, hex.DecodedLen(len(privKey)))
	i, err := hex.Decode(zonePrivateKey, privKey)
	if err != nil {
		log.Error("Was not able to decode privateKey", "path", privateKeyPath, "error", err)
		return err
	}
	if i != ed25519.PrivateKeySize {
		log.Error("Private key length is incorrect", "expected", ed25519.PrivateKeySize, "actual", i)
		return errors.New("Private key length is incorrect")
	}
	return nil
}
