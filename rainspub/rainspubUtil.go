package rainspub

import (
	"encoding/json"
	"io/ioutil"
	"os"

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
		log.Warn("Could not unmarshal json format of config")
	}
}

//TODO CFE remove when we have air gapping
func loadPrivateKey() {
	if _, err := os.Stat(config.ZonePrivateKeyPath); os.IsNotExist(err) {
		var publicKey ed25519.PublicKey
		publicKey, zonePrivateKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			log.Error("Could not generate the zones private key", "error", err)
			return
		}
		storeKeyPair(publicKey, zonePrivateKey)
	} else {
		zonePrivateKey, err = ioutil.ReadFile(config.ZonePrivateKeyPath)
		if err != nil {
			log.Error("Could not read zone private key file", "error", err)
		}
	}
}

func storeKeyPair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	err := ioutil.WriteFile(config.ZonePrivateKeyPath, privateKey, 0644)
	if err != nil {
		log.Error("Could not store the zones private key", "path", config.ZonePrivateKeyPath, "error", err)
	}
	err = ioutil.WriteFile(config.ZonePublicKeyPath, publicKey, 0644)
	if err != nil {
		log.Error("Could not store the zones public key", "path", config.ZonePublicKeyPath, "error", err)
	}
}

//TODO CFE remove when have proper testing. Used to debug
/*func loadPublicKey() ed25519.PublicKey {
	publicKey, err := ioutil.ReadFile(config.ZonePublicKeyPath)
	if err != nil {
		log.Error("Could not read zone private key file", "error", err)
	}
	return publicKey
}*/
