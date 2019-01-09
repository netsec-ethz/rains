package rainsd

import (
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
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

func initStoreCachesContent(config rainsdConfig, caches *Caches, stop chan bool) {
	repeatFuncCaller(func() { checkpoint(config.CheckPointPath, caches.AssertionsCache.Checkpoint) },
		config.AssertionCheckPointInterval, stop)
	repeatFuncCaller(func() { checkpoint(config.CheckPointPath, caches.NegAssertionCache.Checkpoint) },
		config.NegAssertionCheckPointInterval, stop)
	repeatFuncCaller(func() { checkpoint(config.CheckPointPath, caches.ZoneKeyCache.Checkpoint) },
		config.ZoneKeyCheckPointInterval, stop)
}

func checkpoint(path string, values func() []section.Section) {
	io := zonefile.IO{}
	if err := io.EncodeAndStore(path, values()); err != nil {
		log.Error("Was not able to checkpoint assertion cache", "error", err)
	}
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
