package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

const (
	public  = "PublicKey"
	private = "PrivateKey"
)

var keyPath = flag.String("path", "", "Path where the keys are or will be stored.")
var keyName = flag.String("name", "", "Name determines the prefix of the key pair's file name")
var action = flag.String("action", "load", `load or l prints all public keys stored at path. 
generate, gen or g generates a new public-private, stores them at path and prints the public key.
remove or r deletes the keypair at keyPath with keyName.`)
var algo = flag.String("algo", "ed25519", "Algorithm used to generate key")
var phase = flag.Int("phase", 0, "Key phase of the generated key")
var description = flag.String("d", "", "description added when a new key pair is generated")
var pwd = flag.String("pwd", "", "password to used to encrypt a newly generated key pair")

func main() {
	flag.Parse()
	switch *action {
	case "load", "l":
		loadPublicKeys(*keyPath)
	case "generate", "gen", "g":
		generateKey(*keyPath, *keyName, *description, *algo, *pwd, *phase)
	case "remove", "r":
		removeKey(*keyPath, *keyName)
	default:
		log.Error("Unknown action")
		return
	}
}

func loadPublicKeys(keyPath string) {
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		log.Error("Was not able to read directory", "error", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), public) {
			data, err := ioutil.ReadFile(path.Join(keyPath, f.Name()))
			if err != nil {
				log.Error("Was not able to read public key file", "error", err)
				return
			}
			fmt.Println(string(data))
		}
	}
}

func generateKey(keyPath, name, description, algo, pwd string, phase int) {
	var publicKey, privateKey []byte
	var err error
	switch algo {
	case "ed25519":
		if publicKey, privateKey, err = ed25519.GenerateKey(nil); err != nil {
			log.Error("Was not able to generate ed25519 key pair", "error", err)
			return
		}
	case "ed448":
		log.Warn("Not yet supported")
		return
	default:
		log.Error("unsupported algorithm", "algo", algo)
		return
	}
	publicBlock, privateBlock := createPEMBlocks(description, algo, pwd, phase, publicKey, privateKey)
	publicFile, err := os.Create(path.Join(keyPath, name+public))
	if err != nil {
		log.Error("Was not able to create file for public key", "error", err)
		return
	}
	privateFile, err := os.Create(path.Join(keyPath, name+private))
	if err != nil {
		log.Error("Was not able to create file for private key", "error", err)
		return
	}
	if err = pem.Encode(publicFile, publicBlock); err != nil {
		log.Error("Was not able to write public pem block to file", "error", err)
		return
	}
	if err = pem.Encode(privateFile, privateBlock); err != nil {
		log.Error("Was not able to write private pem block to file", "error", err)
		return
	}
}

func createPEMBlocks(description, algo, pwd string, phase int, publicKey, privateKey []byte) (
	blockPublic *pem.Block, blockPrivate *pem.Block) {
	blockPublic = &pem.Block{
		Type: algo + " " + public,
		Headers: map[string]string{
			"keyPhase":    strconv.Itoa(phase),
			"description": description,
		},
		Bytes: publicKey,
	}
	blockPrivate = &pem.Block{
		Type: algo + " Encrypted " + private,
		Headers: map[string]string{
			"keyPhase":    strconv.Itoa(phase),
			"description": description,
		},
		Bytes: privateKey,
	}
	return
}

func removeKey(keyPath, name string) {
	err := os.Remove(path.Join(keyPath, name+public))
	if err != nil {
		log.Error("Was not able to delete public key", "error", err)
	}
	err = os.Remove(path.Join(keyPath, name+private))
	if err != nil {
		log.Error("Was not able to delete private key", "error", err)
	}
}
