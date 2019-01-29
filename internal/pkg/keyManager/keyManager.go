package keyManager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
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
	pubSuffix   = "_pub.pem"
	SecSuffix   = "_sec.pem"
	KeyAlgo     = "keyAlgo"
	KeyPhase    = "keyPhase"
	description = "description"
	salt        = "salt"
	iv          = "iv"
)

//LoadPublicKeys returns all public keys stored in the directory at keypath in pem format.
func LoadPublicKeys(keyPath string) ([]*pem.Block, error) {
	output := []*pem.Block{}
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		log.Error("Was not able to read directory: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), pubSuffix) {
			data, err := ioutil.ReadFile(path.Join(keyPath, f.Name()))
			if err != nil {
				return nil, fmt.Errorf("Was not able to read public key file: %v", err)
			}
			pblock, rest := pem.Decode(data)
			if len(rest) != 0 {
				return nil, fmt.Errorf("Was not able to decode pem encoded public key %s: %v", f.Name(), err)
			}
			output = append(output, pblock)
		}
	}
	return output, nil
}

//GenerateKey generates a keypair according to algo and stores them separately at keyPath/name in
//pem format. The suffix of the filename is either PublicKey or PrivateKey. The private key is
//encrypted using pwd. Both pem blocks contain the description and the key phase in the header. The
//private key pem block additionally has a salt and iv value in the header required for decryption.
func GenerateKey(keyPath, name, description, algo, pwd string, phase int) error {
	var publicKey, privateKey []byte
	var err error
	switch algo {
	case "ed25519":
		if publicKey, privateKey, err = ed25519.GenerateKey(nil); err != nil {
			return fmt.Errorf("Was not able to generate ed25519 key pair: %v", err)
		}
	case "ed448":
		return fmt.Errorf("ed448 key algorithm type not yet supported")
	default:
		return fmt.Errorf("unsupported algorithm: %v", algo)
	}
	publicBlock, privateBlock, err := createPEMBlocks(description, algo, pwd, phase, publicKey, privateKey)
	publicFile, err := os.Create(path.Join(keyPath, name+pubSuffix))
	if err != nil {
		return fmt.Errorf("Was not able to create file for public key: %v", err)
	}
	privateFile, err := os.Create(path.Join(keyPath, name+SecSuffix))
	if err != nil {
		return fmt.Errorf("Was not able to create file for private key: %v", err)
	}
	if err = pem.Encode(publicFile, publicBlock); err != nil {
		return fmt.Errorf("Was not able to write public pem block to file: %v", err)
	}
	if err = pem.Encode(privateFile, privateBlock); err != nil {
		return fmt.Errorf("Was not able to write private pem block to file: %v", err)
	}
	return nil
}

func createPEMBlocks(description, algo, pwd string, phase int, publicKey, privateKey []byte) (
	blockPublic *pem.Block, blockPrivate *pem.Block, err error) {
	blockPublic = &pem.Block{
		Type: "RAINS PUBLIC KEY",
		Headers: map[string]string{
			KeyAlgo:     algo,
			KeyPhase:    strconv.Itoa(phase),
			description: description,
		},
		Bytes: publicKey,
	}
	saltVal, ivVal, ciphertext, err := encryptPrivateKey(pwd, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Was not able to encrypt private key: %v", err)
	}
	blockPrivate = &pem.Block{
		Type: "RAINS ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{
			KeyAlgo:     algo,
			KeyPhase:    strconv.Itoa(phase),
			description: description,
			salt:        hex.EncodeToString(saltVal),
			iv:          hex.EncodeToString(ivVal),
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
func DecryptKey(keyPath, name, pwd string) (*pem.Block, error) {
	data, err := ioutil.ReadFile(path.Join(keyPath, name+SecSuffix))
	if err != nil {
		return nil, fmt.Errorf("Was not able to read private key file: %v", err)
	}
	pblock, rest := pem.Decode(data)
	if len(rest) != 0 {
		return nil, fmt.Errorf("Was not able to decode pem encoded private key: %v", err)
	}
	salt, err := hex.DecodeString(pblock.Headers[salt])
	if err != nil {
		return nil, fmt.Errorf("Was not able to decode salt from pem encoding: %v", err)
	}
	iv, err := hex.DecodeString(pblock.Headers[iv])
	if err != nil {
		return nil, fmt.Errorf("Was not able to decode iv from pem encoding: %v", err)
	}
	dk, err := scrypt.Key([]byte(pwd), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("Was not able to create key from password and salt: %v", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("Was not able to create aes cipher from key: %v", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(pblock.Bytes, pblock.Bytes)
	return pblock, nil
}
