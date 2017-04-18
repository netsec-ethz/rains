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
	"net"
	"rains/rainslib"
	"rains/utils/cache"

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
	serverConnInfo = ConnInfo{Type: TCP, IPAddr: Config.ServerIPAddr, Port: Config.ServerPort}
	loadAuthoritative()
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

func loadAuthoritative() {
	authoritative = make(map[contextAndZone]bool)
	for i, context := range Config.ContextAuthority {
		authoritative[contextAndZone{Context: context, Zone: Config.ZoneAuthority[i]}] = true
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

func sendQuery(context, zone string, expTime int64, objType rainslib.ObjectType, token rainslib.Token, sender ConnInfo) {
	querySection := rainslib.QuerySection{
		Context: context,
		Name:    zone,
		Expires: expTime,
		Token:   token,
		Type:    objType,
	}
	query := rainslib.RainsMessage{Token: token, Content: []rainslib.MessageSection{&querySection}}
	//TODO CFE add infrastructure signature to query message?
	msg, err := msgParser.ParseRainsMsg(query)
	if err != nil {
		log.Warn("Cannot parse a delegation Query", "query", query)
		return
	}
	log.Info("Query sent", "query", querySection)
	sendTo(msg, sender)
}

//getDelegationAddress returns the address of a server to which this server delegates a query if it has no answer in the cache.
func getDelegationAddress(context, zone string) ConnInfo {
	//FIXME CFE not yet implemented
	log.Warn("Not yet implemented CFE. return hard coded delegation address")
	return ConnInfo{Type: TCP, IPAddr: net.ParseIP("127.0.0.1"), Port: 5023}
}

//createConnectionCache returns a newly created connection cache
func createConnectionCache(connCacheSize int) (connectionCache, error) {
	c, err := cache.NewWithEvict(func(value interface{}, key ...string) {
		if value, ok := value.(net.Conn); ok {
			value.Close()
		}
	}, connCacheSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	return &connectionCacheImpl{cache: c}, nil
}

//createCapabilityCache returns a newly created capability cache
func createCapabilityCache(hashToCapCacheSize, connectionToCapSize int) (capabilityCache, error) {
	hc, err := cache.New(hashToCapCacheSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	//FIXME CFE remove this after we can do it in the Add method of the cache
	hc.Add([]Capability{TLSOverTCP}, false, "", "e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745")
	hc.Add([]Capability{NoCapability}, false, "", "76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71")
	cc, err := cache.New(connectionToCapSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	return &capabilityCacheImpl{hashToCap: hc, connInfoToCap: cc}, nil
}

//createKeyCache returns a newly key capability cache
func createKeyCache(keyCacheSize int) (keyCache, error) {
	c, err := cache.New(keyCacheSize, "anyContext")
	if err != nil {
		return nil, err
	}
	return &keyCacheImpl{cache: c}, nil
}

func createPendingSignatureCache(cacheSize int) (pendingSignatureCache, error) {
	c, err := cache.New(cacheSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	return &pendingSignatureCacheImpl{cache: c, maxElements: cacheSize, elementCount: 0}, nil
}

func createPendingQueryCache(cacheSize int) (pendingQueryCache, error) {
	c, err := cache.New(cacheSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	return &pendingQueryCacheImpl{callBackCache: c, maxElements: cacheSize, elementCount: 0, activeTokens: make(map[[16]byte]elemAndValidTo)}, nil
}

func createNegativeAssertionCache(cacheSize int) (negativeAssertionCache, error) {
	c, err := cache.New(cacheSize, "anyContext")
	if err != nil {
		return nil, err
	}
	return &negativeAssertionCacheImpl{cache: c, maxElements: cacheSize, elementCount: 0}, nil

}

func createAssertionCache(cacheSize int) (assertionCache, error) {
	c, err := cache.New(cacheSize, "anyContext")
	if err != nil {
		return nil, err
	}
	return &assertionCacheImpl{assertionCache: c, maxElements: cacheSize, elementCount: 0, rangeMap: make(map[contextAndZone]*sortedAssertionMetaData)}, nil

}
