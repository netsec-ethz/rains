package rainspub

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"encoding/hex"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func loadConfig() {
	loadDefaultSeverAddrIntoConfig()
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Warn("Could not open config file...", "path", configPath, "error", err)
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Warn("Could not unmarshal json format of config", "error", err)
	}
}

//TODO CFE remove when we have air gapping
func loadPrivateKeys() {
	if _, err := os.Stat(config.ZonePrivateKeyPath); os.IsNotExist(err) {
		var publicKey ed25519.PublicKey
		publicKey, zonePrivateKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			log.Error("Could not generate the zones private key", "error", err)
			return
		}
		storeKeyPair(publicKey, zonePrivateKey)
	} else {
		zonePrivateKey = getEd25519PrivateKey(config.ZonePrivateKeyPath)
	}
	rootPrivateKey = getEd25519PrivateKey(config.RootPrivateKeyPath)
}

func getEd25519PrivateKey(path string) ed25519.PrivateKey {
	privKey, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Was not able to read privateKey", "path", path, "error", err)
	}
	privateKey := make([]byte, hex.DecodedLen(len(privKey)))
	i, err := hex.Decode(privateKey, privKey)
	if err != nil {
		log.Error("Was not able to decode privateKey", "path", path, "error", err)
	}
	if i != ed25519.PrivateKeySize {
		log.Error("Private key length is incorrect", "expected", ed25519.PrivateKeySize, "actual", i)
	}
	return privateKey
}

func storeKeyPair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	err := ioutil.WriteFile(config.ZonePrivateKeyPath, []byte(hex.EncodeToString(privateKey)), 0644)
	if err != nil {
		log.Error("Could not store the zones private key", "path", config.ZonePrivateKeyPath, "error", err)
	}
	err = ioutil.WriteFile(config.ZonePublicKeyPath, []byte(hex.EncodeToString(publicKey)), 0644)
	if err != nil {
		log.Error("Could not store the zones public key", "path", config.ZonePublicKeyPath, "error", err)
	}
}
