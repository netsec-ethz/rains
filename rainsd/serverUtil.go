package rainsd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"rains/rainslib"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

const (
	configPath = "config/server.conf"
)

//InitServer initializes the server
func InitServer() error {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(h)
	loadConfig()
	if err := loadCert(); err != nil {
		return err
	}
	if err := initSwitchboard(); err != nil {
		return err
	}
	if err := initInbox(); err != nil {
		return err
	}
	if err := initVerify(); err != nil {
		return err
	}
	if err := initEngine(); err != nil {
		return err
	}

	return nil
}

//LoadConfig loads and stores server configuration
func loadConfig() {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Warn("Could not open config file...", "path", configPath, "error", err)
	}
	if err = json.Unmarshal(file, &Config); err != nil {
		log.Warn("Could not unmarshal json format of config")
	}
}

func loadCert() error {
	roots = x509.NewCertPool()
	file, err := ioutil.ReadFile(Config.CertificateFile)
	if err != nil {
		log.Error("error", err)
		return err
	}
	ok := roots.AppendCertsFromPEM(file)
	if !ok {
		log.Error("failed to parse root certificate")
		return errors.New("failed to parse root certificate")
	}
	return nil
}

//CreateNotificationMsg creates a notification messages
func CreateNotificationMsg(token rainslib.Token, notificationType rainslib.NotificationType, data string) ([]byte, error) {
	content := []rainslib.MessageSection{&rainslib.NotificationSection{Type: rainslib.MsgTooLarge, Token: token, Data: data}}
	msg := rainslib.RainsMessage{Token: rainslib.GenerateToken(), Content: content}
	return msgParser.ParseRainsMsg(msg)
}

//SignData returns a signature of the input data signed with the specified signing algorithm and the given private key.
func SignData(algoType rainslib.SignatureAlgorithmType, privateKey interface{}, data []byte) interface{} {
	switch algoType {
	case rainslib.Ed25519:
		if pkey, ok := privateKey.(ed25519.PrivateKey); ok {
			return ed25519.Sign(pkey, data)
		}
		log.Warn("Could not cast key to ed25519.PrivateKey", "privateKey", privateKey)
	case rainslib.Ed448:
		log.Warn("Ed448 not yet Supported!")
	case rainslib.Ecdsa256:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha256.Sum256(data)
			return signEcdsa(pkey, data, hash[:])
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKey", privateKey)
	case rainslib.Ecdsa384:
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
	r, s, err := ecdsa.Sign(PRG{}, privateKey, hash)
	if err != nil {
		log.Warn("Could not sign data with Ecdsa256", "error", err)
	}
	return []*big.Int{r, s}
}

//VerifySignature returns true if the provided signature with the public key matches the data.
func VerifySignature(algoType rainslib.SignatureAlgorithmType, publicKey interface{}, data []byte, signature interface{}) bool {
	switch algoType {
	case rainslib.Ed25519:
		if pkey, ok := publicKey.(ed25519.PublicKey); ok {
			return ed25519.Verify(pkey, data, signature.([]byte))
		}
		log.Warn("Could not cast key to ed25519.PublicKey", "publicKey", publicKey)
	case rainslib.Ed448:
		log.Warn("Ed448 not yet Supported!")
	case rainslib.Ecdsa256:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := signature.([]*big.Int); ok && len(sig) == 2 {
				hash := sha256.Sum256(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not cast signature ", "signature", signature)
			return false
		}
		log.Warn("Could not cast key to ecdsa.PublicKey", "publicKey", publicKey)
	case rainslib.Ecdsa384:
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
