package rainsd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"path"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

const (
	aCheckPointFileName = "assertionCheckPoint.txt"
	nCheckPointFileName = "negAssertionCheckPoint.txt"
	zCheckPointFileName = "zoneKeyCheckPoint.txt"
)

// trace is a wrapper function which all callees wishing to submit a trace should use,
// as it will only send the trace if a tracer server is connected.
func trace(tok token.Token, msg string) {
	if globalTracer != nil {
		globalTracer.SendMessage(tok, msg)
	}
}

//sendNotificationMsg sends a message containing freshly generated token and a notification section with
//notificationType, token, and data to destination.
func sendNotificationMsg(tok token.Token, destination net.Addr,
	notificationType section.NotificationType, data string, s *Server) {
	notification := &section.Notification{
		Type:  notificationType,
		Token: tok,
		Data:  data,
	}
	sendSection(notification, token.Token{}, destination, s)
}

//sendSections creates a messages containing token and sections and sends it to destination. If
//token is empty, a new token is generated
func sendSections(sections []section.Section, tok token.Token, destination net.Addr, s *Server) error {
	if tok == [16]byte{} {
		tok = token.New()
	}
	msg := message.Message{Token: tok, Content: sections}
	return s.sendTo(msg, destination, 1, 1)
}

//sendSection creates a messages containing token and section and sends it to destination. If
//token is empty, a new token is generated
func sendSection(sec section.Section, token token.Token, destination net.Addr, s *Server) error {
	return sendSections([]section.Section{sec}, token, destination, s)
}

//sendCapability sends a message with capabilities to sender
func sendCapability(destination net.Addr, capabilities []message.Capability, s *Server) {
	msg := message.Message{Token: token.New(), Capabilities: capabilities}
	s.sendTo(msg, destination, 1, 1)
}

//LoadConfig loads and stores server configuration
func loadConfig(configPath string) (rainsdConfig, error) {
	config := rainsdConfig{}
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Warn("Could not open config file...", "path", configPath, "error", err)
		return rainsdConfig{}, err
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Warn("Could not unmarshal json format of config", "error", err)
		return rainsdConfig{}, err
	}
	config.KeepAlivePeriod *= time.Second
	config.TCPTimeout *= time.Second
	config.DelegationQueryValidity *= time.Second
	config.ReapVerifyTimeout *= time.Second
	config.QueryValidity *= time.Second
	config.AddressQueryValidity *= time.Second
	config.ReapEngineTimeout *= time.Second
	config.MaxCacheValidity.AddressAssertionValidity *= time.Hour
	config.MaxCacheValidity.AssertionValidity *= time.Hour
	config.MaxCacheValidity.ShardValidity *= time.Hour
	config.MaxCacheValidity.ZoneValidity *= time.Hour
	return config, nil
}

//loadTLSCertificate load a tls certificate from certPath
func loadTLSCertificate(certPath string, TLSPrivateKeyPath string) (*x509.CertPool, tls.Certificate, error) {
	pool := x509.NewCertPool()
	file, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Error("error", err)
		return nil, tls.Certificate{}, err
	}

	if ok := pool.AppendCertsFromPEM(file); !ok {
		log.Error("failed to parse root certificate")
		return nil, tls.Certificate{}, errors.New("failed to parse root certificate")
	}
	cert, err := tls.LoadX509KeyPair(certPath, TLSPrivateKeyPath)
	if err != nil {
		log.Error("Cannot load certificate. Path to CertificateFile or privateKeyFile might be invalid.",
			"CertPath", certPath, "KeyPath", TLSPrivateKeyPath, "error", err)
		return nil, tls.Certificate{}, err
	}
	return pool, cert, nil
}

//initOwnCapabilities sorts capabilities in lexicographically increasing order.
//It stores the hex encoded sha256 hash of the sorted capabilities to capabilityHash
//and a string representation of the capability list to capabilityList
func initOwnCapabilities(capabilities []message.Capability) (string, string) {
	//TODO CFE when we have CBOR use it to normalize&serialize the array before hashing it.
	//Currently we use the hard coded version from the draft.
	capabilityHash := "e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745"
	cs := make([]string, len(capabilities))
	for i, c := range capabilities {
		cs[i] = string(c)
	}
	return capabilityHash, strings.Join(cs, " ")
}

//loadRootZonePublicKey stores the root zone public key from disk into the zoneKeyCache.
func loadRootZonePublicKey(keyPath string, zoneKeyCache cache.ZonePublicKey,
	maxValidity util.MaxCacheValidity) error {
	a := new(section.Assertion)
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
				keyMap[publicKey.PublicKeyID] = []keys.PublicKey{publicKey}
				if validateSignatures(a, keyMap, maxValidity) {
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

//measureSystemRessources measures current cpu usage
func measureSystemRessources() {
	//Not yet implemented
}

func initStoreCachesContent(config rainsdConfig, caches *Caches, stop chan bool) {
	repeatFuncCaller(func() {
		checkpoint(path.Join(config.CheckPointPath, aCheckPointFileName),
			caches.AssertionsCache.Checkpoint)
	}, config.AssertionCheckPointInterval, stop)
	repeatFuncCaller(func() {
		checkpoint(path.Join(config.CheckPointPath, nCheckPointFileName),
			caches.NegAssertionCache.Checkpoint)
	}, config.NegAssertionCheckPointInterval, stop)
	repeatFuncCaller(func() {
		checkpoint(path.Join(config.CheckPointPath, zCheckPointFileName),
			caches.ZoneKeyCache.Checkpoint)
	}, config.ZoneKeyCheckPointInterval, stop)
}

func checkpoint(path string, values func() []section.Section) {
	io := zonefile.IO{}
	if err := io.EncodeAndStore(path, values()); err != nil {
		log.Error("Was not able to checkpoint assertion cache", "error", err)
	}
}

func loadCaches(cpPath string, caches *Caches, authZone, authContext []string) {
	io := zonefile.IO{}
	//load assertion check point
	sections, err := io.LoadZonefile(path.Join(cpPath, aCheckPointFileName))
	if err != nil {
		log.Warn("Was not able to load assertion check point from file", "error", err)
	}
	for _, s := range sections {
		//TODO check if it is authority
		if s, ok := s.(*section.Assertion); ok {
			caches.AssertionsCache.Add(s, time.Now().Add(24*time.Hour).Unix(),
				isAuthoritative(s, authZone, authContext))
		} else {
			log.Warn("Invalid type for assertion cache", "type", fmt.Sprintf("%T", s))
		}
	}

	//load negAssertion check point
	sections, err = io.LoadZonefile(path.Join(cpPath, nCheckPointFileName))
	if err != nil {
		log.Warn("Was not able to load negAssertion check point from file", "error", err)
	}
	for _, s := range sections {
		switch s := s.(type) {
		case *section.Shard:
			caches.NegAssertionCache.AddShard(s, time.Now().Add(24*time.Hour).Unix(),
				isAuthoritative(s, authZone, authContext))
		case *section.Pshard:
			caches.NegAssertionCache.AddPshard(s, time.Now().Add(24*time.Hour).Unix(),
				isAuthoritative(s, authZone, authContext))
		case *section.Zone:
			caches.NegAssertionCache.AddZone(s, time.Now().Add(24*time.Hour).Unix(),
				isAuthoritative(s, authZone, authContext))
		default:
			log.Warn("Invalid type for negative Assertion cache", "type", fmt.Sprintf("%T", s))
		}
	}

	//load zone key check point
	sections, err = io.LoadZonefile(path.Join(cpPath, zCheckPointFileName))
	if err != nil {
		log.Warn("Was not able to load zone key check point from file", "error", err)
	}
	for _, s := range sections {
		if s, ok := s.(*section.Assertion); ok {
			for _, o := range s.Content {
				if o.Type == object.OTDelegation {
					//TODO check if it is authority
					caches.ZoneKeyCache.Add(s, o.Value.(keys.PublicKey),
						isAuthoritative(s, authZone, authContext))
				}
			}
		} else {
			log.Warn("Invalid type for zone key cache", "type", fmt.Sprintf("%T", s))
		}
	}
}

func isAuthoritative(s section.WithSigForward, authZone, authContext []string) bool {
	isAuthoritative := false
	for i, zone := range authZone {
		if zone == s.GetSubjectZone() && authContext[i] == s.GetContext() {
			isAuthoritative = true
			break
		}
	}
	return isAuthoritative
}

//repeatFuncCaller executes function in intervals of waitTime
func repeatFuncCaller(function func(), waitTime time.Duration, stop chan bool) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		function()
		time.Sleep(waitTime)
	}
}
