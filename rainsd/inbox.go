package rainsd

//add prio1 queue
//add prio2 queue
//create token cache to differentiate self issued and external queries

func init() {
	//TODO CFE initialize both queues and the token cache
	queueWorker()
}

//Deliver handles all incoming messages. It verifies the signatures on the message, parses the query options,
//check expiration date and if it is valid sends it on to the engine which then processes the message.
func Deliver(msg []byte, sender ConnInfo) {
	//TODO check if self issued query
	//TODO CFE push to correct queue

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
