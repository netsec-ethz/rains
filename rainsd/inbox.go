package rainsd

import (
	"fmt"

	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"

	"strings"

	log "github.com/inconshreveable/log15"
)

//incoming messages are buffered in one of these channels until they get processed by a worker go routine
//the prioChannel only contains incoming sections in response to a delegation query issued by this server.
var prioChannel chan msgSectionSender
var normalChannel chan msgSectionSender
var notificationChannel chan msgSectionSender

//These channels limit the number of go routines working on the different queues to avoid memory exhaustion.
var prioWorkers chan struct{}
var normalWorkers chan struct{}
var notificationWorkers chan struct{}

//activeTokens stores the tokens of active delegation queries.
var activeTokens activeTokenCache

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
	capabilities, err = createCapabilityCache(Config.CapabilitiesCacheSize, Config.PeerToCapCacheSize)
	if err != nil {
		log.Error("Cannot create connCache", "error", err)
		return err
	}

	activeTokens = createActiveTokenCache(Config.ActiveTokenCacheSize)

	go workPrio()
	go workNotification()
	go workBoth()

	return nil
}

//deliver pushes all incoming messages to the prio or normal channel.
//A message is added to the priority channel if it is the response to a non-expired delegation query
func deliver(message []byte, sender rainslib.ConnInfo) {
	//check message length
	if uint(len(message)) > Config.MaxMsgByteLength {
		token, _ := msgParser.Token(message)
		sendNotificationMsg(token, sender, rainslib.NTMsgTooLarge, "")
		return
	}
	msg, err := msgParser.Decode(message)
	if err != nil {
		sendNotificationMsg(msg.Token, sender, rainslib.NTBadMessage, "")
		return
	}
	log.Debug("Parsed Message", "msg", msg)

	//FIXME CFE get infrastructure key from cache and if not present send a infra query, add a new cache for whole messages to wait for missing public keys
	if !rainsSiglib.CheckMessageSignatures(&msg, rainslib.PublicKey{}, sigEncoder) {
	}

	processCapability(msg.Capabilities, sender, msg.Token)

	//handle message content
	for _, m := range msg.Content {
		switch m := m.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection, *rainslib.AddressAssertionSection, *rainslib.AddressZoneSection:
			if !isZoneBlacklisted(m.(rainslib.MessageSectionWithSig).GetSubjectZone()) {
				addMsgSectionToQueue(m, msg.Token, sender)
			}
		case *rainslib.QuerySection, *rainslib.AddressQuerySection:
			log.Debug(fmt.Sprintf("add %T to normal queue", m))
			normalChannel <- msgSectionSender{Sender: sender, Section: m, Token: msg.Token}
		case *rainslib.NotificationSection:
			log.Debug("Add notification to notification queue", "token", msg.Token)
			notificationChannel <- msgSectionSender{Sender: sender, Section: m, Token: msg.Token}
		default:
			log.Warn(fmt.Sprintf("unsupported message section type %T", m))
			return
		}
	}
}

//processCapability processes capabilities and sends a notification back to the sender if the hash is not understood.
func processCapability(caps []rainslib.Capability, sender rainslib.ConnInfo, token rainslib.Token) {
	log.Debug("Process capabilities", "capabilities", caps)
	if len(caps) > 0 {
		isHash := !strings.HasPrefix(string(caps[0]), "urn:")
		if isHash {
			if caps, ok := capabilities.Get([]byte(caps[0])); ok {
				connCache.AddCapabilityList(sender, caps)
				sendNotificationMsg(token, sender, rainslib.NTCapabilityAnswer, capabilityHash)
			} else {
				sendNotificationMsg(token, sender, rainslib.NTCapHashNotKnown, capabilityHash)
			}
		} else {
			connCache.AddCapabilityList(sender, &caps)
			sendNotificationMsg(token, sender, rainslib.NTCapabilityAnswer, capabilityHash)
		}
	}
}

//sendNotificationMsg sends a notification message to dst with the given notificationType and capabilityList
func sendNotificationMsg(token rainslib.Token, dst rainslib.ConnInfo,
	notificationType rainslib.NotificationType, capabilityList string) {
	//FIXME CFE when we have CBOR use it to normalize&serialize the array before hashing it.
	//Currently we use the hard coded version from the draft.
	msg := rainslib.NewNotificationMessage(token, notificationType, capabilityList)
	SendMessage(msg, dst)
}

//addMsgSectionToQueue looks up the token of the msg in the activeTokens cache and if present adds the msg section to the prio cache, otherwise to the normal cache.
func addMsgSectionToQueue(msgSection rainslib.MessageSection, tok rainslib.Token, sender rainslib.ConnInfo) {
	if activeTokens.IsPriority(tok) {
		log.Debug("add section with signature to priority queue", "token", tok)
		prioChannel <- msgSectionSender{Sender: sender, Section: msgSection, Token: tok}
	} else {
		log.Debug("add section with signature to normal queue", "token", tok)
		normalChannel <- msgSectionSender{Sender: sender, Section: msgSection, Token: tok}
	}
}

//isZoneBlacklisted returns true if zone is blacklisted
func isZoneBlacklisted(zone string) bool {
	log.Warn("TODO CFE zone blacklist not yet implemented")
	return false
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
//The prio channel is necessary to avoid a blocking of the server. e.g. in the following unrealistic scenario
//1) normal queue fills up with non delegation queries which all are missing a public key
//2) The non-delegation queries get processed by the normalWorkers and added to the pendingSignature cache
//3) For each non-delegation query that gets taken off the queue a new non-delegation query or expired
//   delegation query wins against all waiting valid delegation-queries.
//4) Then although the server is working all the time, no section is added to the caches.
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
