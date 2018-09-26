package rainsd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/token"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

//InitServer initializes the server
func InitServer(configPath, traceAddr, traceSrvID string, logLevel int) error {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(logLevel), h))
	//FIXME CFE replace with cbor parser
	//msgParser = new(protoParser.ProtoParserAndFramer)
	sigEncoder = new(zonefile.Parser)
	if err := loadConfig(configPath); err != nil {
		return err
	}
	log.Debug("Successfully loaded Config")
	serverConnInfo = Config.ServerAddress
	loadAuthoritative(Config.ContextAuthority)
	if err := loadTLSCertificate(Config.TLSCertificateFile, Config.TLSPrivateKeyFile); err != nil {
		return err
	}
	log.Debug("Successfully loaded Certificate")
	initOwnCapabilities(Config.Capabilities)
	initCaches()
	log.Info("Root zone public key path", "value", Config.RootZonePublicKeyPath)
	if err := loadRootZonePublicKey(Config.RootZonePublicKeyPath); err != nil {
		log.Warn("Failed to load root zone public key")
		return err
	}
	log.Info("Successfully loaded root zone public key")
	// XXX(rayhaan): pass shutdown channel from main.
	if err := initQueuesAndWorkers(make(chan bool)); err != nil {
		return err
	}
	log.Debug("Successfully initiated queues and goroutines working on it")
	initEngine()
	log.Debug("Successfully initiated engine")
	// Initialize the tracer
	if traceAddr != "" {
		t, err := NewTracer(traceSrvID, traceAddr)
		if err != nil {
			return fmt.Errorf("failed to initialize the tracer: %v", err)
		}
		globalTracer = t
		go t.SendLoop()
	}
	log.Debug("successfully initialized tracer")
	return nil
}

// trace is a wrapper function which all callees wishing to submit a trace should use,
// as it will only send the trace if a tracer server is connected.
func trace(tok token.Token, msg string) {
	if globalTracer != nil {
		globalTracer.SendMessage(tok, msg)
	}
}

//LoadConfig loads and stores server configuration
//TODO CFE do not load config directly into Config. But load it and then translate/cast elements to Config
func loadConfig(configPath string) error {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Warn("Could not open config file...", "path", configPath, "error", err)
		return err
	}
	if err = json.Unmarshal(file, &Config); err != nil {
		log.Warn("Could not unmarshal json format of config", "error", err)
		return err
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
	return nil
}

//loadAuthoritative stores to authoritative for which zone and context this server has authority.
//Entries over which this server has authority will not be affected by the lru policy of the caches.
func loadAuthoritative(contextAuthorities []string) {
	authoritative = make(map[zoneContext]bool)
	for i, context := range contextAuthorities {
		authoritative[zoneContext{Zone: Config.ZoneAuthority[i], Context: context}] = true
	}
}

//loadRootZonePublicKey stores the root zone public key from disk into the zoneKeyCache.
func loadRootZonePublicKey(keyPath string) error {
	a := new(sections.Assertion)
	err := util.Load(keyPath, a)
	if err != nil {
		log.Warn("Failed to load root zone public key", "err", err)
		return err
	}
	log.Info("Content loaded from root zone public key", "a", a)
	var keysAdded int
	for _, c := range a.Content {
		if c.Type == object.OTDelegation {
			if publicKey, ok := c.Value.(keys.PublicKey); ok {
				keyMap := make(map[keys.PublicKeyID][]keys.PublicKey)
				keyMap[a.Signatures[0].PublicKeyID] = []keys.PublicKey{publicKey}
				if validateSignatures(a, keyMap) {
					if ok := zoneKeyCache.Add(a, publicKey, true); !ok {
						return errors.New("Cache is smaller than the amount of root public keys")
					}
					log.Info("Added root public key to zone key cache.",
						"context", a.Context,
						"zone", a.SubjectZone,
						"RootPublicKey", c.Value,
					)
					keysAdded++
				} else {
					return fmt.Errorf("Failed to validate signature for assertion: %v", a)
				}
			} else {
				log.Warn(fmt.Sprintf("Was not able to cast to keys.PublicKey Got Type:%T", c.Value))
			}
		}
	}
	log.Info("Keys added to zoneKeyCache", "count", keysAdded)
	return err
}

//loadTLSCertificate load a tls certificate from certPath
func loadTLSCertificate(certPath string, TLSPrivateKeyPath string) error {
	roots = x509.NewCertPool()
	file, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Error("error", err)
		return err
	}

	if ok := roots.AppendCertsFromPEM(file); !ok {
		log.Error("failed to parse root certificate")
		return errors.New("failed to parse root certificate")
	}

	if cert, err = tls.LoadX509KeyPair(certPath, TLSPrivateKeyPath); err != nil {
		log.Error("Cannot load certificate. Path to CertificateFile or privateKeyFile might be invalid.",
			"CertPath", certPath, "KeyPath", TLSPrivateKeyPath, "error", err)
		return err
	}
	return nil
}

//initOwnCapabilities sorts capabilities in lexicographically increasing order.
//It stores the hex encoded sha256 hash of the sorted capabilities to capabilityHash
//and a string representation of the capability list to capabilityList
func initOwnCapabilities(capabilities []message.Capability) {
	//TODO CFE when we have CBOR use it to normalize&serialize the array before hashing it.
	//Currently we use the hard coded version from the draft.
	capabilityHash = "e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745"
	cs := make([]string, len(capabilities))
	for i, c := range capabilities {
		cs[i] = string(c)
	}
	capabilityList = strings.Join(cs, " ")
}

//sendSections creates a messages containing token and sections and sends it to destination. If
//token is empty, a new token is generated
func sendSections(sections []sections.Section, tok token.Token, destination connection.Info) error {
	if tok == [16]byte{} {
		tok = token.New()
	}
	msg := message.Message{Token: tok, Content: sections}
	//TODO CFE make retires and backoff configurable
	return sendTo(msg, destination, 1, 1)
}

//sendSection creates a messages containing token and section and sends it to destination. If
//token is empty, a new token is generated
func sendSection(section sections.Section, token token.Token, destination connection.Info) error {
	return sendSections([]sections.Section{section}, token, destination)
}

//sendNotificationMsg sends a message containing freshly generated token and a notification section with
//notificationType, token, and data to destination.
func sendNotificationMsg(tok token.Token, destination connection.Info,
	notificationType sections.NotificationType, data string) {
	notification := &sections.Notification{
		Type:  notificationType,
		Token: tok,
		Data:  data,
	}
	sendSection(notification, token.Token{}, destination)
}

//sendCapability sends a message with capabilities to sender
func sendCapability(destination connection.Info, capabilities []message.Capability) {
	msg := message.Message{Token: token.New(), Capabilities: capabilities}
	sendTo(msg, destination, 1, 1)
}

//getRootAddr returns an addr to a root server.
//FIXME CFE load root addr from config?
func getRootAddr() connection.Info {
	tcpAddr := *Config.ServerAddress.TCPAddr
	tcpAddr.Port++
	rootAddr := connection.Info{Type: Config.ServerAddress.Type, TCPAddr: &tcpAddr}
	log.Warn("Not yet implemented CFE. return hard coded delegation address", "connInfo", rootAddr)
	return rootAddr
}

//createCapabilityCache returns a newly created capability cache
func createCapabilityCache(hashToCapCacheSize int) capabilityCache {
	cache := lruCache.New()
	//TODO CFE after there are more capabilities do not use hardcoded value
	cache.GetOrAdd("e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745",
		[]message.Capability{message.TLSOverTCP}, true)
	cache.GetOrAdd("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71",
		[]message.Capability{message.NoCapability}, false)
	counter := safeCounter.New(hashToCapCacheSize)
	counter.Add(2)
	return &capabilityCacheImpl{capabilityMap: cache, counter: counter}
}
