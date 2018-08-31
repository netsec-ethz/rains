package rainspub

import (
	"crypto/tls"
	"encoding/hex"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"
)

//connectAndSendMsg establishes a connection to server and sends msg. It returns the server info on
//the result channel if it was not able to send the whole msg to it, else nil.
func connectAndSendMsg(msg []byte, server rainslib.ConnInfo, result chan<- *rainslib.ConnInfo) {
	//TODO CFE use certificate for tls
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	switch server.Type {
	case rainslib.TCP:
		conn, err := tls.Dial(server.TCPAddr.Network(), server.String(), conf)
		if err != nil {
			log.Error("Was not able to establish a connection.", "server", server, "error", err)
			result <- &server
			return
		}

		msgFramer := new(protoParser.ProtoParserAndFramer)
		msgFramer.InitStreams(conn, conn)
		token, _ := msgFramer.Token(msg)
		success := make(chan bool)
		go listen(msgFramer, conn, token, success)
		err = msgFramer.Frame(msg)
		if err != nil {
			conn.Close()
			log.Error("Was not able to frame the message.", "msg", msg, "server", server, "error", err)
			result <- &server
			return
		}

		if <-success {
			log.Debug("Successful published information.", "serverAddresses", server.String())
			result <- nil
		} else {
			result <- &server
		}
	default:
		log.Error("Unsupported connection information type.", "connType", server.Type)
		result <- &server
	}
}

//listen receives incoming messages for one second. If the message's token matches the query's
//token, it handles the response.
func listen(msgFramer *protoParser.ProtoParserAndFramer, conn net.Conn, token rainslib.Token, success chan<- bool) {
	//close connection after 1 second assuming everything went well
	deadline := make(chan bool)
	result := make(chan bool)
	go func() {
		time.Sleep(time.Second)
		deadline <- true
	}()
	go waitForResponse(msgFramer, conn, token, result)
	for true {
		select {
		case <-deadline:
			conn.Close()
			success <- true
			return
		case err := <-result:
			if err {
				success <- false
			} else {
				go waitForResponse(msgFramer, conn, token, result)
			}
		}
	}

}

func waitForResponse(msgFramer *protoParser.ProtoParserAndFramer, conn net.Conn,
	token rainslib.Token, serverError chan<- bool) {
	for msgFramer.DeFrame() {
		_, err := msgFramer.Token(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to extract the token", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			serverError <- false
			return
		}
		msg, err := msgFramer.Decode(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to decode received message", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			serverError <- false
			return
		}
		//Rainspub only accepts notification messages in response to published information.
		if n, ok := msg.Content[0].(*rainslib.NotificationSection); ok && n.Token == token {
			if handleResponse(conn, msg.Content[0].(*rainslib.NotificationSection)) {
				conn.Close()
				serverError <- true
				return
			}
			serverError <- false
			return
		}
		log.Debug("Token of sent message does not match the token of the received message",
			"messageToken", token, "recvToken", msg.Token)
	}
}

//handleResponse handles the received notification message and returns true if the connection can
//be closed.
func handleResponse(conn net.Conn, n *rainslib.NotificationSection) bool {
	switch n.Type {
	case rainslib.NTHeartbeat, rainslib.NTNoAssertionsExist, rainslib.NTNoAssertionAvail:
	//nop
	case rainslib.NTCapHashNotKnown:
	//TODO CFE send back the whole capability list in an empty message
	case rainslib.NTBadMessage:
		log.Error("Sent msg was malformed", "data", n.Data)
	case rainslib.NTRcvInconsistentMsg:
		log.Error("Sent msg was inconsistent", "data", n.Data)
	case rainslib.NTMsgTooLarge:
		log.Error("Sent msg was too large", "data", n.Data)
		//What should we do in this case. apparently it is not possible to send a zone because
		//it is too large. send shards instead?
	case rainslib.NTUnspecServerErr:
		log.Error("Unspecified error of other server", "data", n.Data)
		//TODO CFE resend?
	case rainslib.NTServerNotCapable:
		log.Error("Other server was not capable", "data", n.Data)
		//TODO CFE when can this occur?
	default:
		log.Error("Received non existing notification type")
	}
	return false
}
