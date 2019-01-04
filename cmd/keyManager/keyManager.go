package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

const (
	public  = "PublicKey"
	private = "PrivateKey"
)

var keyPath = flag.String("path", "", "Path where the keys are or will be stored.")
var keyName = flag.String("name", "", "Name determines the prefix of the key pair's file name")
var action = flag.String("action", "load", `load or l prints all public keys stored at path. 
generate, gen or g generates a new public-private, stores them at path and prints the public key.
remove or r deletes the keypair at keyPath with keyName. decrypt or d decrypts the private key 
specified by keyName using pwd and printing it.`)
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
	case "decrypt", "d":
		decryptKey(*keyPath, *keyName, *pwd)
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
	salt, iv, ciphertext, err := encryptPrivateKey(pwd, privateKey)
	if err != nil {
		log.Error("Was not able to encrypt private key")
	}
	blockPrivate = &pem.Block{
		Type: algo + " Encrypted " + private,
		Headers: map[string]string{
			"keyPhase":    strconv.Itoa(phase),
			"description": description,
			"salt":        hex.EncodeToString(salt),
			"iv":          hex.EncodeToString(iv),
		},
		Bytes: ciphertext,
	}
	return
}

func encryptPrivateKey(pwd string, privateKey []byte) (salt, iv, ciphertext []byte, err error) {
	salt = make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, err
	}

	dk, err := scrypt.Key([]byte(pwd), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, nil, nil, err
	}

	ciphertext = make([]byte, len(privateKey))
	iv = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, privateKey)
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

func decryptKey(keyPath, name, pwd string) {
	data, err := ioutil.ReadFile(path.Join(keyPath, name+private))
	if err != nil {
		log.Error("Was not able to read private key file", "error", err)
		return
	}
	pblock, rest := pem.Decode(data)
	if len(rest) != 0 {
		log.Error("Was not able to decode pem encoded private key", "error", err)
	}
	salt, err := hex.DecodeString(pblock.Headers["salt"])
	if err != nil {
		log.Error("Was not able to decode salt from pem encoding", "error", err)
	}
	iv, err := hex.DecodeString(pblock.Headers["iv"])
	if err != nil {
		log.Error("Was not able to decode iv from pem encoding", "error", err)
	}
	dk, err := scrypt.Key([]byte(pwd), salt, 1<<15, 8, 1, 32)
	if err != nil {
		log.Error("Was not able to create key from password and salt", "error", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		log.Error("Was not able to create aes cipher from key", "error", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(pblock.Bytes, pblock.Bytes)
	fmt.Printf("%s", pem.EncodeToMemory(pblock))
}
