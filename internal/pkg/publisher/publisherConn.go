package publisher

import (
	"crypto/tls"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//connectAndSendMsg establishes a connection to server and sends msg. It returns the server info on
//the result channel if it was not able to send the whole msg to it, else nil.
func connectAndSendMsg(msg message.Message, server connection.Info, result chan<- *connection.Info) {
	//TODO CFE use certificate for tls
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	switch server.Type {
	case connection.TCP:
		conn, err := tls.Dial(server.TCPAddr.Network(), server.String(), conf)
		if err != nil {
			log.Error("Was not able to establish a connection.", "server", server, "error", err)
			result <- &server
			return
		}
		success := make(chan bool)
		go listen(conn, msg.Token, success)
		writer := borat.NewCBORWriter(conn)
		if err := writer.Marshal(&msg); err != nil {
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
func listen(conn net.Conn, token token.Token, success chan<- bool) {
	//close connection after 1 second assuming everything went well
	deadline := make(chan bool)
	result := make(chan bool)
	go func() {
		time.Sleep(time.Second)
		deadline <- true
	}()
	go waitForResponse(conn, token, result)
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
				go waitForResponse(conn, token, result)
			}
		}
	}

}

func waitForResponse(conn net.Conn, token token.Token, serverError chan<- bool) {
	reader := borat.NewCBORReader(conn)
	var msg message.Message
	if err := reader.Unmarshal(&msg); err != nil {
		log.Warn("Was not able to decode received message", "error", err)
		serverError <- false
		return
	}
	//Rainspub only accepts notification messages in response to published information.
	if n, ok := msg.Content[0].(*sections.Notification); ok && n.Token == token {
		if handleResponse(conn, msg.Content[0].(*sections.Notification)) {
			conn.Close()
			serverError <- true
			return
		}
		serverError <- false
		return
	}
	//TODO CFE do we need the token?
	log.Debug("Token of sent message does not match the token of the received message",
		"messageToken", token, "recvToken", msg.Token)
}

//handleResponse handles the received notification message and returns true if the connection can
//be closed.
func handleResponse(conn net.Conn, n *sections.Notification) bool {
	switch n.Type {
	case sections.NTHeartbeat, sections.NTNoAssertionsExist, sections.NTNoAssertionAvail:
	//nop
	case sections.NTCapHashNotKnown:
	//TODO CFE send back the whole capability list in an empty message
	case sections.NTBadMessage:
		log.Error("Sent msg was malformed", "data", n.Data)
	case sections.NTRcvInconsistentMsg:
		log.Error("Sent msg was inconsistent", "data", n.Data)
	case sections.NTMsgTooLarge:
		log.Error("Sent msg was too large", "data", n.Data)
		//What should we do in this case. apparently it is not possible to send a zone because
		//it is too large. send shards instead?
	case sections.NTUnspecServerErr:
		log.Error("Unspecified error of other server", "data", n.Data)
		//TODO CFE resend?
	case sections.NTServerNotCapable:
		log.Error("Other server was not capable", "data", n.Data)
		//TODO CFE when can this occur?
	default:
		log.Error("Received non existing notification type")
	}
	return false
}
