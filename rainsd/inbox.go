package rainsd

import (
	"fmt"

	"rains/rainslib"

	log "github.com/inconshreveable/log15"
)

//incoming messages are buffered in one of these channels until they get processed by a worker go routine
var prioChannel chan msgSectionSender
var normalChannel chan msgSectionSender
var notificationChannel chan msgSectionSender

//These channels limit the number of go routines working on the queue to avoid memory exhaustion.
var prioWorkers chan struct{}
var normalWorkers chan struct{}
var notificationWorkers chan struct{}

//activeTokens contains tokens created by this server (indicate self issued queries)
//TODO create a mechanism such that this map does not grow too much in case of an attack. -> If the token is evicted before answer -> answer comes not on prio queue.
//Solution: if full do not add it to cache and these answers are then not handled with priority.???
var activeTokens = make(map[[16]byte]bool)

//capabilities stores known hashes of capabilities and for each connInfo what capability the communication partner has.
var capabilities capabilityCache

func initInbox() error {
	//init Channels
	prioChannel = make(chan msgSectionSender, Config.PrioBufferSize)
	normalChannel = make(chan msgSectionSender, Config.NormalBufferSize)
	notificationChannel = make(chan msgSectionSender, Config.NotificationBufferSize)

	//init max amount of concurrent workers
	prioWorkers = make(chan struct{}, Config.PrioWorkerCount)
	normalWorkers = make(chan struct{}, Config.NormalWorkerCount)
	notificationWorkers = make(chan struct{}, Config.NotificationWorkerCount)

	//init Capability Cache
	var err error
	capabilities, err = createCapabilityCache(int(Config.CapabilitiesCacheSize), int(Config.PeerToCapCacheSize))
	if err != nil {
		log.Error("Cannot create connCache", "error", err)
		return err
	}

	go workPrio()
	go workNotification()
	go workBoth()

	return nil
}

//addToActiveTokenCache adds tok to the active tocken cache
func addToActiveTokenCache(tok string) {
	if len(tok) > 16 {
		tok = tok[:16]
	}
	var token [16]byte
	copy(token[0:len(tok)], []byte(tok))
	activeTokens[token] = true
}

//deliver pushes all incoming messages to the prio or normal channel based on some strategy
func deliver(message []byte, sender rainslib.ConnInfo) {
	//check message length
	if uint(len(message)) > Config.MaxMsgByteLength {
		token, _ := msgParser.Token(message)
		sendNotificationMsg(token, sender, rainslib.MsgTooLarge)
		return
	}

	msg, err := msgParser.Decode(message)
	if err != nil {
		sendNotificationMsg(msg.Token, sender, rainslib.BadMessage)
		return
	}
	log.Info("Parsed Message", "msg", msg)

	processCapability(msg.Capabilities, sender, msg.Token)

	if !verifyMessageSignature(msg) {
		return
	}

	//handle message content
	for _, m := range msg.Content {
		switch m := m.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection, *rainslib.AddressAssertionSection, *rainslib.AddressZoneSection:
			addMsgSectionToQueue(m, msg.Token, sender)
		case *rainslib.QuerySection:
			addQueryToQueue(m.Token, msg.Token, m, sender)
		case *rainslib.AddressQuerySection:
			addQueryToQueue(m.Token, msg.Token, m, sender)
		case *rainslib.NotificationSection:
			addNotificationToQueue(m, msg.Token, sender)
		default:
			log.Warn(fmt.Sprintf("unsupported message section type %T", m))
		}
	}
}

//processCapability processes capabilities and sends a notification back to the sender if the hash is not understood.
func processCapability(caps []rainslib.Capability, sender rainslib.ConnInfo, token rainslib.Token) {
	log.Debug("Process capabilities", "capabilities", caps)
	if len(caps) > 0 {
		//TODO CFE determine when an incoming capability is represented as a hash
		log.Error("test")
		isHash := false
		if isHash {
			if caps, ok := capabilities.GetFromHash([]byte(caps[0])); ok {
				capabilities.Add(sender, caps)
				handleCapabilities(caps)
			} else {
				sendNotificationMsg(token, sender, rainslib.CapHashNotKnown)
			}
		} else {
			capabilities.Add(sender, caps)
			handleCapabilities(caps)
		}
	}
}

//handleCapabilities takes appropriate actions depending on the capability of the communication partner
func handleCapabilities(caps []rainslib.Capability) {
	log.Warn("Capability handling is not yet implemented")
	/*for _, capa := range caps {
		switch capa {
		case rainslib.TLSOverTCP:
			//TODO CFE impl
		case rainslib.NoCapability:
			//Do nothing
		default:
			log.Warn("Sent capability value does not match know capability", "rcvCaps", capa)
		}
	}*/
}

//sendNotificationMsg sends a notification message to the sender with the given notificationType. If an error occurs during parsing no message is sent and the error is logged.
func sendNotificationMsg(token rainslib.Token, sender rainslib.ConnInfo, notificationType rainslib.NotificationType) {
	msg, err := CreateNotificationMsg(token, notificationType, "")
	if err != nil {
		log.Warn("Cannot send notification error due to parser error", "error", err)
		return
	}
	sendTo(msg, sender)
}

//addMsgSectionToQueue looks up the token of the msg in the activeTokens cache and if present adds the msg section to the prio cache, otherwise to the normal cache.
func addMsgSectionToQueue(msgSection rainslib.MessageSection, tok rainslib.Token, sender rainslib.ConnInfo) {
	if _, ok := activeTokens[tok]; ok {
		log.Debug("add section with signature to priority queue", "token", tok)
		prioChannel <- msgSectionSender{Sender: sender, Section: msgSection, Token: tok}
	} else {
		log.Debug("add section with signature to normal queue", "token", tok)
		normalChannel <- msgSectionSender{Sender: sender, Section: msgSection, Token: tok}
	}
}

//addQueryToQueue checks that the token of the message and of the query section are the same and if so adds it to a queue
func addQueryToQueue(queryToken, msgToken rainslib.Token, section rainslib.MessageSection, sender rainslib.ConnInfo) {
	if msgToken == queryToken {
		log.Debug("add query to normal queue")
		normalChannel <- msgSectionSender{Sender: sender, Section: section, Token: msgToken}
	} else {
		log.Warn("Token of message and query section do not match.", "msgToken", msgToken, "querySectionToken", queryToken)
		//Tokens do not match in query. We do not know which one is valid. Send BadMessage Notification back to both tokens
		sendNotificationMsg(msgToken, sender, rainslib.BadMessage)
		sendNotificationMsg(queryToken, sender, rainslib.BadMessage)
	}
}

//addNotificationToQueue adds a rains message containing one notification message section to the queue if the token is present in the activeToken cache
func addNotificationToQueue(msg *rainslib.NotificationSection, tok rainslib.Token, sender rainslib.ConnInfo) {
	if _, ok := activeTokens[tok]; ok {
		//FIXME CFE right now we only have one cache for tokens (sent out message) where we only store the token when it is priority.
		//We should have a maximum number of queries we sent out and wait for and after that drop every incoming request that wants access. So we can ensure that we handle
		// at least some request.
		//As we have it now with a fixed pending query cache, if there are a lot of incoming request this queue fills up and until the answer arrived all elements were discarded
		//and we cannot serve anyone!
		log.Info("Add notification to notification queue", "token", tok)
		//We do not delete the token when we receive a capability hash not understood because the other server will still process the message.
		//In all other cases the other server stops processing the message and we can safely delete the token.
		if msg.Type != rainslib.CapHashNotKnown {
			delete(activeTokens, tok)
		}
		notificationChannel <- msgSectionSender{Sender: sender, Section: msg, Token: msg.Token}
	} else {
		log.Warn("Token not in active token cache, drop message", "token", tok)
	}
}

//workBoth works on the prioChannel and on the normalChannel. A worker only fetches a message from the normalChannel if the prioChannel is empty.
//the channel normalWorkers enforces a maximum number of go routines working on the prioChannel and normalChannel.
func workBoth() {
	for {
		normalWorkers <- struct{}{}
		select {
		case msg := <-prioChannel:
			go prioWorkerHandler(msg)
			continue
		default:
			//do nothing
		}
		select {
		case msg := <-normalChannel:
			go normalWorkerHandler(msg)
		default:
			<-normalWorkers
		}
	}
}

//normalWorkerHandler handles sections on the normalChannel
func normalWorkerHandler(msg msgSectionSender) {
	verify(msg)
	<-normalWorkers
}

//workPrio works on the prioChannel. It waits on the prioChannel and creates a new go routine which handles the section.
//the channel prioWorkers enforces a maximum number of go routines working on the prioChannel.
//The prio channel is necessary to avoid a deadlock
func workPrio() {
	for {
		prioWorkers <- struct{}{}
		msg := <-prioChannel
		go prioWorkerHandler(msg)
	}
}

//prioWorkerHandler handles sections on the prioChannel
func prioWorkerHandler(msg msgSectionSender) {
	verify(msg)
	<-prioWorkers
}

//workNotification works on the notificationChannel. It waits on the notificationChannel and creates a new go routine which handles the notification.
//the channel notificationWorkers enforces a maximum number of go routines working on the notificationChannel
func workNotification() {
	for {
		notificationWorkers <- struct{}{}
		msg := <-notificationChannel
		go handleNotification(msg)
	}
}

//handleNotification works on notificationChannel.
func handleNotification(msg msgSectionSender) {
	notify(msg)
	<-notificationWorkers
}
