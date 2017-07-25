package rainsd

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/cache"
	"github.com/netsec-ethz/rains/utils/protoParser"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"

	log "github.com/inconshreveable/log15"
)

//InitServer initializes the server
func InitServer(configPath string) error {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, h))
	loadConfig(configPath)
	serverConnInfo = Config.ServerAddress
	msgParser = new(protoParser.ProtoParserAndFramer)
	sigEncoder = new(zoneFileParser.Parser)
	loadAuthoritative(Config.ContextAuthority)
	if err := loadCert(Config.TLSCertificateFile); err != nil {
		return err
	}
	log.Debug("Successfully loaded Certificate")
	if err := initSwitchboard(); err != nil {
		return err
	}
	log.Debug("Successfully initiated switchboard")
	if err := initInbox(); err != nil {
		return err
	}
	log.Debug("Successfully initiated inbox")
	if err := initVerify(); err != nil {
		return err
	}
	log.Debug("Successfully initiated verify")
	if err := initEngine(); err != nil {
		return err
	}
	log.Debug("Successfully initiated engine")
	return nil
}

//LoadConfig loads and stores server configuration
//FIXME CFE do not load config directly into Config. But load it and then translate/cast elements to Config
func loadConfig(configPath string) {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Warn("Could not open config file...", "path", configPath, "error", err)
	}
	if err = json.Unmarshal(file, &Config); err != nil {
		log.Warn("Could not unmarshal json format of config", "error", err)
	}
	Config.KeepAlivePeriod *= time.Second
	Config.TCPTimeout *= time.Second
	Config.DelegationQueryValidity *= time.Second
	Config.ReapVerifyTimeout *= time.Second
	Config.QueryValidity *= time.Second
	Config.AddressQueryValidity *= time.Second
	Config.ReapEngineTimeout *= time.Second
	Config.MaxCacheValidity.AddressAssertionValidity *= time.Hour
	Config.MaxCacheValidity.AddressZoneValidity *= time.Hour
	Config.MaxCacheValidity.AssertionValidity *= time.Hour
	Config.MaxCacheValidity.ShardValidity *= time.Hour
	Config.MaxCacheValidity.ZoneValidity *= time.Hour
}

//loadAuthoritative stores to authoritative for which zone and context this server has authority.
//Entries over which this server has authority will not be affected by the lru policy of the caches.
func loadAuthoritative(contextAuthorities []string) {
	authoritative = make(map[contextAndZone]bool)
	for i, context := range contextAuthorities {
		authoritative[contextAndZone{Context: context, Zone: Config.ZoneAuthority[i]}] = true
	}
}

//loadRootZonePublicKey stores the root zone public key from disk into the zoneKeyCache.
func loadRootZonePublicKey(keyPath string) error {
	a := new(rainslib.AssertionSection)
	err := rainslib.Load(keyPath, a)
	if err == nil {
		for _, c := range a.Content {
			if c.Type == rainslib.OTDelegation {
				if publicKey, ok := c.Value.(rainslib.PublicKey); ok {
					keyMap := make(map[rainslib.SignatureAlgorithmType]rainslib.PublicKey)
					keyMap[a.Signatures[0].Algorithm] = publicKey
					if validateSignatures(a, keyMap) {
						log.Info("Added root public key to zone key cache.", "context", a.Context, "zone", a.SubjectZone, "RootPublicKey", c.Value)
						zoneKeyCache.Add(keyCacheKey{context: a.Context, zone: a.SubjectZone, keyAlgo: publicKey.Type}, publicKey, true)
					}
				} else {
					log.Warn(fmt.Sprintf("Was not able to cast to rainslib.PublicKey Got Type:%T", c.Value))
				}
			}
		}
	}
	return err
}

//loadCert load a tls certificate from certPath
func loadCert(certPath string) error {
	roots = x509.NewCertPool()
	file, err := ioutil.ReadFile(certPath)
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

//SendMessage adds an infrastructure signature to message and encodes it. Then it is sent to addr.
//In case of an encoder error, it logs message information and the error.
func SendMessage(message rainslib.RainsMessage, dst rainslib.ConnInfo) error {
	//FIXME CFE add infrastructure signatured
	msg, err := msgParser.Encode(message)
	if err != nil {
		log.Warn("Cannot encode message", "message", message, "error", err)
		return err
	}
	log.Debug("Send message", "message", message)
	return sendTo(msg, dst, 1, 1)
}

//getDelegationAddress returns the address of a server to which this server delegates a query if it has no answer in the cache.
func getDelegationAddress(context, zone string) rainslib.ConnInfo {
	//TODO CFE not yet implemented
	tcpAddr := *Config.ServerAddress.TCPAddr
	tcpAddr.Port++
	delegAddr := rainslib.ConnInfo{Type: Config.ServerAddress.Type, TCPAddr: &tcpAddr}
	log.Warn("Not yet implemented CFE. return hard coded delegation address", "connInfo", delegAddr)
	return delegAddr
}

//createConnectionCache returns a newly created connection cache
func createConnectionCache(connCacheSize uint) (connectionCache, error) {
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
func createCapabilityCache(hashToCapCacheSize, connectionToCapSize uint) (capabilityCache, error) {
	hc, err := cache.New(hashToCapCacheSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	//FIXME move adding this values to verify.init() after cache was adopted
	hc.Add([]Capability{TLSOverTCP}, false, "", "e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745")
	hc.Add([]Capability{NoCapability}, false, "", "76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71")
	cc, err := cache.New(connectionToCapSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	return &capabilityCacheImpl{hashToCap: hc, connInfoToCap: cc}, nil
}

//createKeyCache returns a new key capability cache
func createKeyCache(keyCacheSize uint) (keyCache, error) {
	c, err := cache.New(keyCacheSize, "anyContext")
	if err != nil {
		return nil, err
	}
	return &keyCacheImpl{cache: c}, nil
}

//createPendingSignatureCache returns a new pending signature cache
func createPendingSignatureCache(cacheSize uint) (pendingSignatureCache, error) {
	c, err := cache.New(cacheSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	return &pendingSignatureCacheImpl{cache: c, maxElements: cacheSize, elementCount: 0}, nil
}

//createPendingQueryCache returns a new pending query cache
func createPendingQueryCache(cacheSize uint) (pendingQueryCache, error) {
	c, err := cache.New(cacheSize, "noAnyContext")
	if err != nil {
		return nil, err
	}
	return &pendingQueryCacheImpl{callBackCache: c, maxElements: cacheSize, elementCount: 0, activeTokens: make(map[[16]byte]elemAndValidTo)}, nil
}

//createNegativeAssertionCache returns a new negative assertion cache
func createNegativeAssertionCache(cacheSize uint) (negativeAssertionCache, error) {
	c, err := cache.New(cacheSize, "anyContext")
	if err != nil {
		return nil, err
	}
	return &negativeAssertionCacheImpl{cache: c, maxElements: cacheSize, elementCount: 0}, nil

}

//createAssertionCache returns a new assertion cache
func createAssertionCache(cacheSize uint) (assertionCache, error) {
	c, err := cache.New(cacheSize, "anyContext")
	if err != nil {
		return nil, err
	}
	return &assertionCacheImpl{
		assertionCache: c,
		maxElements:    cacheSize,
		elementCount:   0,
		rangeMap:       make(map[contextAndZone]*sortedAssertionMetaData),
	}, nil
}

//createActiveTokenCache returns a new active token cache
func createActiveTokenCache(cacheSize uint) activeTokenCache {
	return &activeTokenCacheImpl{maxElements: cacheSize, elementCount: 0, activeTokenCache: make(map[rainslib.Token]int64)}
}
