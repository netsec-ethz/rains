package rainsd

import (
	"errors"
	"fmt"

	"github.com/netsec-ethz/rains/internal/pkg/token"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

// trace is a wrapper function which all callees wishing to submit a trace should use,
// as it will only send the trace if a tracer server is connected.
func trace(tok token.Token, msg string) {
	if globalTracer != nil {
		globalTracer.SendMessage(tok, msg)
	}
}

//loadRootZonePublicKey stores the root zone public key from disk into the zoneKeyCache.
func loadRootZonePublicKey(keyPath string) error {
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

//sendSections creates a messages containing token and sections and sends it to destination. If
//token is empty, a new token is generated
func sendSections(sections []section.Section, tok token.Token, destination connection.Info) error {
	if tok == [16]byte{} {
		tok = token.New()
	}
	msg := message.Message{Token: tok, Content: sections}
	//TODO CFE make retires and backoff configurable
	return sendTo(msg, destination, 1, 1)
}

//sendSection creates a messages containing token and section and sends it to destination. If
//token is empty, a new token is generated
func sendSection(sec section.Section, token token.Token, destination connection.Info) error {
	return sendSections([]section.Section{sec}, token, destination)
}

//sendNotificationMsg sends a message containing freshly generated token and a notification section with
//notificationType, token, and data to destination.
func sendNotificationMsg(tok token.Token, destination connection.Info,
	notificationType section.NotificationType, data string) {
	notification := &section.Notification{
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
