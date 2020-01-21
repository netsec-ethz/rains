package publisher

import (
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

//connectAndSendMsg establishes a connection to server and sends msg. It returns the server info on
//the result channel if it was not able to send the whole msg to it, else nil.
func connectAndSendMsg(msg message.Message, server net.Addr) error {

	conn, err := connection.CreateConnection(server)
	if err != nil {
		return fmt.Errorf("unable to establish a connection: %s", err)
	}
	defer conn.Close()
	err = connection.WriteMessage(conn, &msg)
	if err != nil {
		return fmt.Errorf("unable send message: %s", err)
	}

	// Wait 1 second for reply
	deadline := time.Now().Add(1 * time.Second)
	conn.SetReadDeadline(deadline)
	for deadline.After(time.Now()) {
		replyMsg, err := connection.ReceiveMessage(conn)
		if err != nil {
			//only accept notification messages in response to published information.
			if n, ok := replyMsg.Content[0].(*section.Notification); ok && n.Token == msg.Token {
				if handleResponse(msg.Content[0].(*section.Notification)) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("timeout while waiting for response")
}

//handleResponse handles the received notification message and returns true if the connection can
//be closed.
func handleResponse(n *section.Notification) bool {
	switch n.Type {
	case section.NTHeartbeat, section.NTNoAssertionsExist, section.NTNoAssertionAvail:
	//nop
	case section.NTCapHashNotKnown:
	//TODO CFE send back the whole capability list in an empty message
	case section.NTBadMessage:
		log.Error("Sent msg was malformed", "data", n.Data)
	case section.NTRcvInconsistentMsg:
		log.Error("Sent msg was inconsistent", "data", n.Data)
	case section.NTMsgTooLarge:
		log.Error("Sent msg was too large", "data", n.Data)
		//What should we do in this case. apparently it is not possible to send a zone because
		//it is too large. send shards instead?
	case section.NTUnspecServerErr:
		log.Error("Unspecified error of other server", "data", n.Data)
		//TODO CFE resend?
	case section.NTServerNotCapable:
		log.Error("Other server was not capable", "data", n.Data)
		//TODO CFE when can this occur?
	default:
		log.Error("Received non existing notification type")
	}
	return false
}
