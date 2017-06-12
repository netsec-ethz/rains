package rainslib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/gob"
	"math/big"
	"os"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func init() {
	gob.Register(ed25519.PublicKey{})
}

//GenerateToken generates a new unique Token
func GenerateToken() Token {
	token := [16]byte{}
	_, err := rand.Read(token[:])
	if err != nil {
		log.Warn("Error during random token generation", "error", err)
	}
	return Token(token)
}

//SignData returns a signature of the input data signed with the specified signing algorithm and the given private key.
func SignData(algoType SignatureAlgorithmType, privateKey interface{}, data []byte) interface{} {
	switch algoType {
	case Ed25519:
		if pkey, ok := privateKey.(ed25519.PrivateKey); ok {
			return ed25519.Sign(pkey, data)
		}
		log.Warn("Could not cast key to ed25519.PrivateKey", "privateKey", privateKey)
	case Ed448:
		log.Warn("Ed448 not yet Supported!")
	case Ecdsa256:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha256.Sum256(data)
			return signEcdsa(pkey, data, hash[:])
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKey", privateKey)
	case Ecdsa384:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha512.Sum384(data)
			return signEcdsa(pkey, data, hash[:])
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKey", privateKey)
	default:
		log.Warn("Signature algorithm type not supported", "type", algoType)
	}
	return nil
}

func signEcdsa(privateKey *ecdsa.PrivateKey, data, hash []byte) interface{} {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		log.Warn("Could not sign data with Ecdsa256", "error", err)
	}
	return []*big.Int{r, s}
}

//VerifySignature returns true if the provided signature with the public key matches the data.
func VerifySignature(algoType SignatureAlgorithmType, publicKey interface{}, data []byte, signature interface{}) bool {
	switch algoType {
	case Ed25519:
		//log.Debug("", "byteStub", data, "publicKey", publicKey, "sigData", signature)
		if pkey, ok := publicKey.(ed25519.PublicKey); ok {
			return ed25519.Verify(pkey, data, signature.([]byte))
		}
		log.Warn("Could not cast key to ed25519.PublicKey", "publicKey", publicKey)
	case Ed448:
		log.Warn("Ed448 not yet Supported!")
	case Ecdsa256:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := signature.([]*big.Int); ok && len(sig) == 2 {
				hash := sha256.Sum256(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not cast signature ", "signature", signature)
			return false
		}
		log.Warn("Could not cast key to ecdsa.PublicKey", "publicKey", publicKey)
	case Ecdsa384:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := signature.([]*big.Int); ok && len(sig) == 2 {
				hash := sha512.Sum384(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not cast signature ", "signature", signature)
			return false
		}
		log.Warn("Could not cast key to ecdsa.PublicKey", "publicKey", publicKey)
	default:
		log.Warn("Signature algorithm type not supported", "type", algoType)
	}
	return false
}

//Save stores the object to the file located at the specified path gob encoded.
func Save(path string, object interface{}) error {
	file, err := os.Create(path)
	defer file.Close()
	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(object)
	}
	return err
}

//Load fetches the gob encoded object from the file located at path
func Load(path string, object interface{}) error {
	file, err := os.Open(path)
	defer file.Close()
	if err == nil {
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(object)
	}
	return err
}
