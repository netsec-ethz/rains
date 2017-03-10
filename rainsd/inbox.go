package rainsd

//Deliver handles all incoming messages. It verifies the signatures on the message, parses the query options,
//check expiration date and if it is valid sends it on to the engine which then processes the message.
func Deliver(message RainsMessage, sender ConnInfo) {

}
