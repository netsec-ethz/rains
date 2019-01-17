package keyManager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
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
	pubSuffix = "_pub.pem"
	secSuffix = "_sec.pem"
)

//LoadPublicKeys returns all public keys stored in the directory at keypath in pem format.
func LoadPublicKeys(keyPath string) string {
	output := []string{}
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		log.Error("Was not able to read directory", "error", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), pubSuffix) {
			data, err := ioutil.ReadFile(path.Join(keyPath, f.Name()))
			if err != nil {
				log.Error("Was not able to read public key file", "error", err)
				return ""
			}
			output = append(output, string(data))
		}
	}
	return strings.Join(output, "\n")
}

//GenerateKey generates a keypair according to algo and stores them separately at keyPath/name in
//pem format. The suffix of the filename is either PublicKey or PrivateKey. The private key is
//encrypted using pwd. Both pem blocks contain the description and the key phase in the header. The
//private key pem block additionally has a salt and iv value in the header required for decryption.
func GenerateKey(keyPath, name, description, algo, pwd string, phase int) {
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
	publicFile, err := os.Create(path.Join(keyPath, name+pubSuffix))
	if err != nil {
		log.Error("Was not able to create file for public key", "error", err)
		return
	}
	privateFile, err := os.Create(path.Join(keyPath, name+secSuffix))
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
		Type: "RAINS PUBLIC KEY",
		Headers: map[string]string{
			"keyAlgo":     algo,
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
		Type: "RAINS ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{
			"keyAlgo":     algo,
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

//DecryptKey decryptes the private key stored at keyPath/name with pwd and returns it in pem format.
func DecryptKey(keyPath, name, pwd string) *pem.Block {
	data, err := ioutil.ReadFile(path.Join(keyPath, name+secSuffix))
	if err != nil {
		log.Error("Was not able to read private key file", "error", err)
		return nil
	}
	pblock, rest := pem.Decode(data)
	if len(rest) != 0 {
		log.Error("Was not able to decode pem encoded private key", "error", err)
		return nil
	}
	salt, err := hex.DecodeString(pblock.Headers["salt"])
	if err != nil {
		log.Error("Was not able to decode salt from pem encoding", "error", err)
		return nil
	}
	iv, err := hex.DecodeString(pblock.Headers["iv"])
	if err != nil {
		log.Error("Was not able to decode iv from pem encoding", "error", err)
		return nil
	}
	dk, err := scrypt.Key([]byte(pwd), salt, 1<<15, 8, 1, 32)
	if err != nil {
		log.Error("Was not able to create key from password and salt", "error", err)
		return nil
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		log.Error("Was not able to create aes cipher from key", "error", err)
		return nil
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(pblock.Bytes, pblock.Bytes)
	return pblock
}
