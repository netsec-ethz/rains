package rainsd

import (
	"bytes"
	"rains/rainslib"
	"rains/utils/parser"
	"time"

	log "github.com/inconshreveable/log15"
)

//incoming messages are buffered in one of these channels until they get processed by a worker go routine
var prioChannel chan MsgBodySender
var normalChannel chan MsgBodySender
var notificationChannel chan MsgBodySender

//activeTokens contains tokens created by this server (indicate self issued queries)
//TODO create a mechanism such that this map does not grow too much in case of an attack.
//Have a counter (Buffered channel) and block in verify step if too many queries open
var activeTokens = make(map[[32]byte]bool)

//capabilities contains a map with key <hash of a set of capabilities> value <[]capabilities>
var capabilities Cache

//capabilities contains a map with key ConnInfo value <capabilities>
var peerToCapability Cache

var msgParser rainslib.RainsMsgParser

//TODO CFE remove later: utility only used for testing purposes
func addToken(s string) {
	if len(s) > 32 {
		s = s[:32]
	}
	var token [32]byte
	copy(token[0:len(s)], []byte(s))
	activeTokens[token] = true
}

func init() {
	//TODO CFE remove after we have proper starting procedure.
	var err error
	loadConfig()
	prioChannel = make(chan MsgBodySender, Config.PrioBufferSize)
	normalChannel = make(chan MsgBodySender, Config.NormalBufferSize)
	notificationChannel = make(chan MsgBodySender, Config.NotificationBufferSize)
	createWorker()
	//TODO CFE for testing purposes (afterwards remove)
	addToken("456")
	capabilities = &LRUCache{}
	err = capabilities.New(int(Config.CapabilitiesCacheSize))
	if err != nil {
		log.Error("Cannot create capabilitiesCache", "error", err)
		panic(err)
	}
	capabilities.Add("e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745", []Capability{TLSOverTCP})
	capabilities.Add("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71", []Capability{NoCapability})
	peerToCapability = &LRUCache{}
	err = peerToCapability.New(int(Config.PeerToCapCacheSize))
	if err != nil {
		log.Error("Cannot create peerToCapability", "error", err)
		panic(err)
	}
	//init parser
	msgParser = parser.RainsMsgParser{}
}

//Deliver pushes all incoming messages to the prio or normal channel based on some strategy
func Deliver(message []byte, sender ConnInfo) {
	if uint(len(message)) > Config.MaxMsgLength {
		token, _ := msgParser.Token(message)
		sendNotificationMsg(token, sender, rainslib.MsgTooLarge)
		return
	}
	msg, err := msgParser.ParseByteSlice(message)
	if err != nil {
		sendNotificationMsg(msg.Token, sender, rainslib.RcvMalformatMsg)
		return
	}
	log.Info("Parsed Message", "Msg", msg)
	//TODO CFE this part must be refactored once we have a CBOR parser so we can distinguish an array of capabilities from a sha has entry
	if msg.Capabilities != "" {
		if caps, ok := capabilities.Get(msg.Capabilities); ok {
			peerToCapability.Add(sender, caps)
		} else {
			switch Capability(msg.Capabilities) {
			case TLSOverTCP:
				peerToCapability.Add(sender, TLSOverTCP)
			case NoCapability:
				peerToCapability.Add(sender, NoCapability)
			default:
				log.Warn("Sent capability value does not match know capability", "rcvCaps", msg.Capabilities)
			}
		}
	}
	//TODO CFE verify signatures against infrastructure key for the RAINS Server originating the message
	for _, m := range msg.Content {
		switch m := m.(type) {
		case *rainslib.AssertionBody:
			addMsgBodyToQueue(m, msg.Token, sender)
		case *rainslib.ShardBody:
			addMsgBodyToQueue(m, msg.Token, sender)
		case *rainslib.QueryBody:
			addQueryToQueue(m, msg, sender)
		case *rainslib.NotificationBody:
			addNotifToQueue(m, msg.Token, sender)
		default:
			log.Warn("Unknown message type")
		}
	}
}

//sendNotificationMsg sends a notification message to the sender with the given notificationType. If an error occurs during parsing no message is sent and the error is logged.
func sendNotificationMsg(token rainslib.Token, sender ConnInfo, notificationType rainslib.NotificationType) {
	msg, err := CreateNotificationMsg(token, notificationType, "")
	if err != nil {
		return
	}
	SendTo(msg, sender)
}

//addMsgBodyToQueue looks up the token of the msg in the activeTokens cache and if present adds the msg body to the prio cache, otherwise to the normal cache.
func addMsgBodyToQueue(msgBody rainslib.MessageBody, tok rainslib.Token, sender ConnInfo) {
	var token [32]byte
	copy(token[0:len(tok)], tok)
	if _, ok := activeTokens[token]; ok {
		log.Info("active Token encountered", "Token", token)
		prioChannel <- MsgBodySender{Sender: sender, Msg: msgBody, Token: tok}
	} else {
		log.Info("token not in active token cache", "Token", token)
		normalChannel <- MsgBodySender{Sender: sender, Msg: msgBody, Token: tok}
	}
}

//addQueryToQueue checks that the token of the message and of the query body are the same and if so adds it to a queue
func addQueryToQueue(body *rainslib.QueryBody, msg rainslib.RainsMessage, sender ConnInfo) {
	if bytes.Equal(msg.Token, body.Token) {
		normalChannel <- MsgBodySender{Sender: sender, Msg: body, Token: msg.Token}
	} else {
		log.Warn("Token of message and query body do not match.", "msgToken", msg.Token, "queryBodyToken", body.Token)
		sendNotificationMsg(msg.Token, sender, rainslib.RcvMalformatMsg)
		sendNotificationMsg(body.Token, sender, rainslib.RcvMalformatMsg)
	}
}

//addNotifToQueue adds a rains message containing one notification message body to the queue if the token is present in the activeToken cache
func addNotifToQueue(msg *rainslib.NotificationBody, tok rainslib.Token, sender ConnInfo) {
	var token [32]byte
	copy(token[0:len(msg.Token)], msg.Token)
	if _, ok := activeTokens[token]; ok {
		log.Info("active Token encountered", "Token", token)
		delete(activeTokens, token)
		notificationChannel <- MsgBodySender{Sender: sender, Msg: msg, Token: tok}
	} else {
		log.Warn("Token not in active token cache, drop message", "Token", token)
	}
}

//createWorker creates go routines which process messages from the prioChannel and normalChannel.
//number of go routines per queue are loaded from the config
func createWorker() {
	for i := 0; i < int(Config.PrioWorkerSize); i++ {
		go workPrio()
	}
	for i := 0; i < int(Config.NormalWorkerSize); i++ {
		go workBoth()
	}
	for i := 0; i < int(Config.NotificationWorkerSize); i++ {
		go workNotification()
	}
}

//workBoth works on the prioChannel and on the normalChannel. A worker only fetches a message from the normalChannel if the prioChannel is empty
func workBoth() {
	for {
	innerLoop:
		for {
			select {
			case msg := <-prioChannel:
				Verify(msg)
			default:
				break innerLoop
			}
		}

		select {
		case msg := <-normalChannel:
			Verify(msg)
		default:
			//TODO CFE add to config?
			time.Sleep(50 * time.Millisecond)
		}
	}
}

//workPrio only works on prioChannel. This is necessary to avoid deadlock
func workPrio() {
	for {
		select {
		case msg := <-prioChannel:
			Verify(msg)
		default:
			//TODO CFE add to config?
			time.Sleep(50 * time.Millisecond)
		}
	}
}

//workNotification works on notificationChannel.
func workNotification() {
	for {
		select {
		case msg := <-notificationChannel:
			Notify(msg)
		default:
			//TODO CFE add to config?
			time.Sleep(50 * time.Millisecond)
		}
	}
}
