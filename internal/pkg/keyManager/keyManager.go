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
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/util"
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
	HexEncoding = "hexEncoding"
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
			pblock, err := loadPemBlock(keyPath, f.Name())
			if err != nil {
				return nil, err
			}
			output = append(output, pblock)
		}
	}
	return output, nil
}

func loadPemBlock(folder, name string) (*pem.Block, error) {
	data, err := ioutil.ReadFile(path.Join(folder, name))
	if err != nil {
		return nil, fmt.Errorf("Was not able to read key file: %v", err)
	}
	pblock, rest := pem.Decode(data)
	if len(rest) != 0 {
		return nil, fmt.Errorf("Was not able to decode pem encoded key %s: %v", name, err)
	}
	return pblock, nil
}

//GenerateKey generates a keypair according to algo and stores them separately at keyPath/name in
//pem format. The suffix of the filename is either PublicKey or PrivateKey. The private key is
//encrypted using pwd. Both pem blocks contain the description and the key phase in the header. The
//private key pem block additionally has a salt and iv value in the header required for decryption.
//Returns the public key in pem format or an error
func GenerateKey(keyPath, name, description, algo, pwd string, phase int) (*pem.Block, error) {
	var publicKey, privateKey []byte
	algoType, err := algorithmTypes.AtoSig(algo)
	switch algoType {
	case algorithmTypes.Ed25519:
		if publicKey, privateKey, err = ed25519.GenerateKey(nil); err != nil {
			return nil, fmt.Errorf("Was not able to generate ed25519 key pair: %v", err)
		}
	case algorithmTypes.Ed448:
		return nil, fmt.Errorf("ed448 key algorithm type not yet supported")
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", algo)
	}
	publicBlock, privateBlock, err := createPEMBlocks(description, algo, pwd, phase, publicKey, privateKey)
	publicFile, err := os.Create(path.Join(keyPath, name+pubSuffix))
	if err != nil {
		return nil, fmt.Errorf("Was not able to create file for public key: %v", err)
	}
	privateFile, err := os.Create(path.Join(keyPath, name+SecSuffix))
	if err != nil {
		return nil, fmt.Errorf("Was not able to create file for private key: %v", err)
	}
	if err = pem.Encode(publicFile, publicBlock); err != nil {
		return nil, fmt.Errorf("Was not able to write public pem block to file: %v", err)
	}
	if err = pem.Encode(privateFile, privateBlock); err != nil {
		return nil, fmt.Errorf("Was not able to write private pem block to file: %v", err)
	}
	return publicBlock, nil
}

func createPEMBlocks(description, algo, pwd string, phase int, publicKey, privateKey []byte) (
	blockPublic *pem.Block, blockPrivate *pem.Block, err error) {
	blockPublic = &pem.Block{
		Type: "RAINS PUBLIC KEY",
		Headers: map[string]string{
			KeyAlgo:     algo,
			KeyPhase:    strconv.Itoa(phase),
			description: description,
			HexEncoding: hex.EncodeToString(publicKey),
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
	pblock, err := loadPemBlock(keyPath, name)
	if err != nil {
		return nil, err
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

//PemToKeyID decodes a pem encoded private key into a publicKeyID and a privateKey Object
func PemToKeyID(block *pem.Block) (keyID keys.PublicKeyID, pkey interface{}, err error) {
	phase, err := strconv.Atoi(block.Headers[KeyPhase])
	if err != nil {
		return keys.PublicKeyID{}, nil, fmt.Errorf("Was not able to parse key phase from pem: %v", err)
	}
	algo, err := algorithmTypes.AtoSig(block.Headers[KeyAlgo])
	if err != nil {
		return keys.PublicKeyID{}, nil, fmt.Errorf("Was not able to parse key algorithm from pem %v", err)
	}
	keyID = keys.PublicKeyID{
		Algorithm: algo,
		KeyPhase:  phase,
		KeySpace:  keys.RainsKeySpace,
	}
	switch algo {
	case algorithmTypes.Ed25519:
		pkey = ed25519.PrivateKey(block.Bytes)
	case algorithmTypes.Ed448:
		return keys.PublicKeyID{}, nil, fmt.Errorf("not yet supported signature algo type: %v", algo)
	default:
		return keys.PublicKeyID{}, nil, fmt.Errorf("unsupported signature algo type: %v", algo)
	}
	return
}

//SelfSignedDelegation creates, self signs, and stores a delgation assertion for the key pair with
//name at path.
func SelfSignedDelegation(srcPath, dstPath, pwd, zone, context string, validityPeriod time.Duration) error {
	folder, file := path.Split(srcPath)
	block, err := DecryptKey(folder, file+SecSuffix, pwd)
	if err != nil {
		return err
	}
	keyID, privateKey, err := PemToKeyID(block)
	if err != nil {
		return err
	}
	pubBlock, err := loadPemBlock(folder, file+pubSuffix)
	if err != nil {
		return err
	}
	pkey := keys.PublicKey{
		PublicKeyID: keyID,
		Key:         ed25519.PublicKey(pubBlock.Bytes),
	}
	assertion := &section.Assertion{
		SubjectName: "@",
		SubjectZone: zone,
		Context:     context,
		Content:     []object.Object{object.Object{Type: object.OTDelegation, Value: pkey}},
	}
	sig := signature.Sig{
		PublicKeyID: keyID,
		ValidSince:  time.Now().Unix(),
		ValidUntil:  time.Now().Add(validityPeriod).Unix(),
	}
	assertion.AddSig(sig)
	ks := map[keys.PublicKeyID]interface{}{pkey.PublicKeyID: privateKey}
	if err := siglib.SignSectionUnsafe(assertion, ks); err != nil {
		return err
	}
	return util.Save(dstPath, assertion)
}
