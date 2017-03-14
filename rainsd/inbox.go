package rainsd

import (
	log "github.com/inconshreveable/log15"
)

//there is always at least one worker actively working on this channel
var prioChannel = make(chan []byte, Config.PrioBufferSize)
var normalChannel = make(chan []byte, Config.NormalBufferSize)

//create token cache to differentiate self issued and external queries

func init() {
	//TODO CFE initialize both queues and the token cache
	queueWorker()
}

//Deliver pushes all incoming messages to the prio or normal channel based on some strategy
func Deliver(msg []byte, sender ConnInfo) {
	//TODO CFE change to full data model
	t := string(msg[0:3])
	switch t {
	case ":A:", ":S:", ":Z:":
		log.Info("Received assertion, shard or zone", "msg", msg)
		//TODO CFE check if token was issued from this server as strategy to put in prioChannel
		normalChannel <- msg
	case ":Q:":
		log.Info("Received query", "msg", msg)
		normalChannel <- msg
	case ":N:":
		log.Info("Received notification", "msg", msg)
		//TODO CFE check if token was issued from this server as strategy to put in prioChannel
		normalChannel <- msg
	default:
		log.Warn("Unknown message type")
	}

	//TODO CFE remove after next step is done
	SendTo([]byte("new message"), sender)
}

func queueWorker() {
	//TODO CFE create go routines (handleMessage) which process the messages on the queue
}

func handleMessage(msg string) {
	msg = Verify(msg)
	//TODO CFE parse query options
	//TODO CFE check expiration date
	//TODO CFE forward packet
}
