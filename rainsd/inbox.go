package rainsd

import (
	"errors"
	"fmt"
	"rains/rainslib"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
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
var capabilities *lru.Cache

//capabilities contains a map with key <context,zone>? value <capabilities> //we cannot store only hash of capabilities because we then do not know the mapping back.
//TODO CFE make an interface such that different cache implementation can be used in the future -> same as switchboard
var peerToCapability *lru.Cache

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
	capabilities, err = lru.New(int(Config.CapabilitiesCacheSize))
	if err != nil {
		log.Error("Cannot create capabilitiesCache", "error", err)
		panic(err)
	}
	//TODO CFE add Config entry if this cache is necessary
	peerToCapability, err = lru.New(100)
	if err != nil {
		log.Error("Cannot create peerToCapability", "error", err)
		panic(err)
	}
}

//Deliver pushes all incoming messages to the prio or normal channel based on some strategy
func Deliver(message []byte, sender ConnInfo) {
	msg, err := parseShortMsg(message)
	if err != nil {
		//TODO format message correctly. This is a invalid notification
		SendTo([]byte(":N: Msg malformated"), sender)
		return
	}
	//TODO CFE check capabilities
	for _, m := range msg.Content {
		//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		//TODO problem, we have several message sections but channel are messages. -> when do we assign something in the priority channel?
		//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		switch m.(type) {
		case rainslib.AssertionBody:
			var token [32]byte
			copy(token[0:len(msg.Token)], msg.Token)
			if _, ok := activeTokens[token]; ok {
				log.Info("active Token encountered", "Token", token)
				prioChannel <- MsgSender{Sender: sender, Msg: msg}
			} else {
				log.Info("token not in active token cache", "Token", token)
				normalChannel <- MsgSender{Sender: sender, Msg: msg}
			}
		case rainslib.QueryBody:
			normalChannel <- MsgSender{Sender: sender, Msg: msg}
		case rainslib.NotificationBody:
			//TODO CFE should we handle notifications in a separate buffer as we do not expect a lot of them and in case of
			//Capability hash not understood or Message too large we instantly want to resend it to reduce query latency.
			prioChannel <- MsgSender{Sender: sender, Msg: msg}
		default:
			log.Warn("Unknown message type")
		}
	}
}

//parseMsg change the representation from a byte slice to a RainsMessage
//We use the following formats:
//simple Signed Assertion: :SA::TM:<token>:CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:OT:<object type>:OD:<object data>signature
//simple Query: :Q::TM:<token>:VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>
//simple Notification: :N::TM:<token of msg>:TN:<token this notification refers to>:NT:<type>:ND:<data>
//signature == :VF:<valid-from>:VU:<valid-until>:KA:<key-algorithm>:SD:<signature-data>:sig:
//NOT YET SUPPORTED
//simple Contained Assertion: :CA::SN:<subject-name>:OT:<object type>:OD:<object data>
//simple Contained Shard: :CS::RB:<range-begin>:RE:<range-end>[Contained Assertion*]
//simple Signed Shard: :SS::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
//simple Zone: :Z::CN:<context-name>:ZN:<zone-name>[Contained Shard* | Contained Assertion*]
func parseShortMsg(message []byte) (rainslib.RainsMessage, error) {
	msg := string(message)
	t := msg[0:3]
	switch t {
	case ":SA:":
		return parseSignedAssertion(msg)
	case ":Q:":
		return parseQuery(msg)
	case ":N:":
		return parseNotification(msg)
	default:
		log.Warn("Unknown or Unsupported message type")
		return rainslib.RainsMessage{}, errors.New("Unknown or Unsupported message type")
	}
}

//parseSignedAssertion parses a signed assertion message section body
func parseSignedAssertion(msg string) (rainslib.RainsMessage, error) {
	log.Info("Received signed assertion", "msg", msg)
	tm := strings.Index(msg, ":TM:")
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	od := strings.Index(msg, ":OD:")
	vs := strings.Index(msg, ":VS:")
	vu := strings.Index(msg, ":VU:")
	ka := strings.Index(msg, ":KA:")
	sd := strings.Index(msg, ":SD:")
	sig := strings.Index(msg, ":sig:")
	if tm == -1 || zn == -1 || cn == -1 || sn == -1 || ot == -1 || od == -1 || vs == -1 || vu == -1 || ka == -1 || sd == -1 || sig == -1 {
		log.Warn("Assertion Msg Body malformated")
		return rainslib.RainsMessage{}, errors.New("Assertion Msg Body malformated")
	}
	objType, err := strconv.Atoi(msg[ot+4 : od])
	if err != nil {
		log.Warn("objType malformated")
		return rainslib.RainsMessage{}, errors.New("objType malformated")
	}
	validSince, err := strconv.Atoi(msg[vs+4 : vu])
	if err != nil {
		log.Warn("validSince malformated")
		return rainslib.RainsMessage{}, errors.New("validSince malformated")
	}
	validUntil, err := strconv.Atoi(msg[vu+4 : ka])
	if err != nil {
		log.Warn("validUntil malformated")
		return rainslib.RainsMessage{}, errors.New("validUntil malformated")
	}
	cipherType, err := strconv.Atoi(msg[ka+4 : sd])
	if err != nil {
		log.Warn("cipher malformated")
		return rainslib.RainsMessage{}, errors.New("cipher malformated")
	}
	object := rainslib.Object{Type: rainslib.ObjectType(objType), Value: msg[od+4 : vs]}
	signature := rainslib.Signature{Algorithm: rainslib.CipherType(cipherType), ValidSince: validSince, ValidUntil: validUntil, Data: []byte(msg[sd+4 : sig])}
	content := []rainslib.MessageBody{rainslib.AssertionBody{SubjectZone: msg[zn+4 : sn], Context: msg[cn+4 : zn], SubjectName: msg[sn+4 : ot],
		Content: object, Signature: signature}}
	return rainslib.RainsMessage{Token: rainslib.Token(msg[tm+4 : cn]), Content: content}, nil
}

//parseQuery parses a query message section body
func parseQuery(msg string) (rainslib.RainsMessage, error) {
	log.Info("Received query", "msg", msg)
	tm := strings.Index(msg, ":TM:")
	vu := strings.Index(msg, ":VU:")
	cn := strings.Index(msg, ":CN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	if tm == -1 || vu == -1 || cn == -1 || sn == -1 || ot == -1 {
		log.Warn("Query Msg Body malformated")
		return rainslib.RainsMessage{}, errors.New("Query Msg Body malformated")
	}
	expires, err := strconv.Atoi(msg[vu+4 : cn])
	if err != nil {
		log.Warn("Valid Until malformated")
		return rainslib.RainsMessage{}, errors.New("Valid Until malformated")
	}
	objType, err := strconv.Atoi(msg[ot+4 : len(msg)])
	if err != nil {
		log.Warn("objType malformated")
		return rainslib.RainsMessage{}, errors.New("objType malformated")
	}
	content := []rainslib.MessageBody{rainslib.QueryBody{Token: rainslib.Token(msg[tm+4 : vu]),
		Expires: expires, Context: msg[cn+4 : sn], SubjectName: msg[sn+4 : ot], Types: rainslib.ObjectType(objType)}}
	return rainslib.RainsMessage{Token: rainslib.Token(msg[tm+4 : vu]), Content: content}, nil
}

//parseNotification parses a notification message section body
func parseNotification(msg string) (rainslib.RainsMessage, error) {
	log.Info("Received notification", "msg", msg)
	//TODO CFE should we handle notifications in a separate buffer as we do not expect a lot of them and in case of
	//Capability hash not understood or Message too large we instantly want to resend it to reduce query latency.
	tm := strings.Index(msg, ":TM:")
	tn := strings.Index(msg, ":TN:")
	nt := strings.Index(msg, ":NT:")
	nd := strings.Index(msg, ":ND:")
	if tm == -1 || tn == -1 || nt == -1 || nd == -1 {
		log.Warn("Notification Msg Body malformated")
		return rainslib.RainsMessage{}, errors.New("Notification Msg Body malformated")
	}
	fmt.Println(msg[nt:nd])
	ntype, err := strconv.Atoi(msg[nt+4 : nd])
	if err != nil {
		log.Warn("Notification Type malformated")
		return rainslib.RainsMessage{}, errors.New("notification type malformated")
	}
	content := []rainslib.MessageBody{rainslib.NotificationBody{Token: rainslib.Token(msg[tn+4 : nt]), Type: rainslib.NotificationType(ntype), Data: msg[nd+4 : len(msg)]}}
	return rainslib.RainsMessage{Token: rainslib.Token(msg[tm+4 : tn]), Content: content}, nil
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
