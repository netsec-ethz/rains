package rainsd

import (
	"rains/rainslib"
	"rains/utils/parser"
	"time"

	log "github.com/inconshreveable/log15"
)

//incoming messages are buffered in one of these channels until they get processed by a worker go routine
var prioChannel chan MsgSender
var normalChannel chan MsgSender

//activeTokens contains tokens created by this server (indicate self issued queries)
//TODO create a mechanism such that this map does not grow too much in case of an attack.
//Have a counter (Buffered channel) and block in verify step if too many queries open
var activeTokens = make(map[[32]byte]bool)

//capabilities contains a map with key <hash of a set of capabilities> value <capabilities>
//TODO how do we want to handle the interaction between those 2 caches.
//TODO CFE make an interface such that different cache implementation can be used in the future -> same as switchboard
var capabilities Cache

//capabilities contains a map with key <context,zone>? value <capabilities> //we cannot store only hash of capabilities because we then do not know the mapping back.
//TODO CFE make an interface such that different cache implementation can be used in the future -> same as switchboard
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
	prioChannel = make(chan MsgSender, Config.PrioBufferSize)
	normalChannel = make(chan MsgSender, Config.NormalBufferSize)
	createWorker()
	//TODO CFE for testing purposes (afterwards remove)
	addToken("asdf")
	capabilities = &LRUCache{}
	err = capabilities.New(int(Config.CapabilitiesCacheSize))
	if err != nil {
		log.Error("Cannot create capabilitiesCache", "error", err)
		panic(err)
	}
	//TODO CFE add Config entry if this cache is necessary
	peerToCapability = &LRUCache{}
	err = peerToCapability.New(100)
	if err != nil {
		log.Error("Cannot create peerToCapability", "error", err)
		panic(err)
	}
	//init parser
	msgParser = parser.RainsMsgParser{}
}

//Deliver pushes all incoming messages to the prio or normal channel based on some strategy
func Deliver(message []byte, sender ConnInfo) {
	msg, err := msgParser.ParseByteSlice(message)
	if err != nil {
		//TODO format message correctly. This is a invalid notification
		SendTo([]byte(":N: Msg malformated"), sender)
		return
	}
	//TODO CFE check capabilities
	for _, m := range msg.Content {
		switch m.(type) {
		case rainslib.AssertionBody:
			var token [32]byte
			copy(token[0:len(msg.Token)], msg.Token)
			if _, ok := activeTokens[token]; ok {
				log.Info("active Token encountered", "Token", token)
				prioChannel <- MsgSender{Sender: sender, Msg: m}
			} else {
				log.Info("token not in active token cache", "Token", token)
				normalChannel <- MsgSender{Sender: sender, Msg: m}
			}
		case rainslib.QueryBody:
			normalChannel <- MsgSender{Sender: sender, Msg: m}
		case rainslib.NotificationBody:
			//TODO CFE should we handle notifications in a separate buffer as we do not expect a lot of them and in case of
			//Capability hash not understood or Message too large we instantly want to resend it to reduce query latency.
			prioChannel <- MsgSender{Sender: sender, Msg: m}
		default:
			log.Warn("Unknown message type")
		}
	}
}

//createWorker creates go routines which process messages from the prioChannel and normalChannel.
//number of go routines per queue are loaded from the config
func createWorker() {
	prio := Config.PrioWorkerSize
	normal := Config.NormalWorkerSize
	if prio == 0 || normal == 0 {
		log.Warn("Size of workers for the normal or for the priority channel is 0! We use default values")
		prio = defaultConfig.PrioWorkerSize
		normal = defaultConfig.NormalWorkerSize
	}
	for i := 0; i < int(prio); i++ {
		go workPrio()
	}
	for i := 0; i < int(normal); i++ {
		go workBoth()
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
