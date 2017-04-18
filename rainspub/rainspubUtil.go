package rainspub

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func loadConfig() {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Warn("Could not open config file...", "path", configPath, "error", err)
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Warn("Could not unmarshal json format of config")
	}
}

func loadKeyPair() {
	//TODO CFE store key pair somewhere, right now we always generate new ones.
	var err error
	publicKey, privateKey, err = generateKeyPair()
	if err != nil {
		log.Warn("Could not load private/public key pair")
	}
}

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	if err != nil {
		log.Warn("Was not able to generate public and private key pair using ed25519.GenerateKey()", "error", err)
	}
	return publicKey, privateKey, err
}
