package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/scionproto/scion/go/lib/sciond"
	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

//connectAndSendMsg establishes a connection to server and sends msg. It returns the server info on
//the result channel if it was not able to send the whole msg to it, else nil.
func connectAndSendMsg(ctx context.Context, msg message.Message, server net.Addr, srcAddr connection.Info, result chan<- net.Addr) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	switch server.(type) {
	case *net.TCPAddr:
		conn, err := tls.Dial(server.Network(), server.String(), conf)
		if err != nil {
			log.Error("Was not able to establish a connection.", "server", server, "error", err)
			result <- server
			return
		}
		success := make(chan bool)
		go listen(conn, msg.Token, success)
		writer := cbor.NewWriter(conn)
		if err := writer.Marshal(&msg); err != nil {
			conn.Close()
			log.Error("Was not able to frame the message.", "msg", msg, "server", server, "error", err)
			result <- server
			return
		}

		if <-success {
			log.Debug("Successful published information.", "serverAddresses", server.String())
			result <- nil
		} else {
			result <- server
		}
	case *snet.Addr:
		if srcAddr.Type != connection.SCION {
			log.Error("SrcAddr must be specified and be set to a SCION address.")
			result <- server
			return
		}
		SCIONSrc, ok := srcAddr.Addr.(*snet.Addr)
		if !ok {
			log.Error(fmt.Sprintf("srcAddr.Addr must be an *snet.Addr, but was: %T", srcAddr.Addr))
			result <- server
			return
		}
		saddr := server.(*snet.Addr)
		if !SCIONSrc.IA.Equal(saddr.IA) {
			pathEntry := choosePath(ctx, SCIONSrc, saddr)
			if pathEntry == nil {
				log.Error(fmt.Sprintf("failed to find path from %s to %s", SCIONSrc, saddr))
				result <- server
				return
			}
			saddr.Path = spath.New(pathEntry.Path.FwdPath)
			if err := saddr.Path.InitOffsets(); err != nil {
				log.Error(fmt.Sprintf("failed to InitOffsets on remote SCION address: %v", err))
				result <- server
				return
			}
			saddr.NextHop, _ = pathEntry.HostInfo.Overlay()
		}
		conn, err := snet.DialSCION("udp4", SCIONSrc, saddr)
		if err != nil {
			log.Error(fmt.Sprintf("failed to DialSCION: %v", err))
			result <- server
			return
		}
		encoding := new(bytes.Buffer)
		if err := cbor.NewWriter(encoding).Marshal(&msg); err != nil {
			log.Error(fmt.Sprintf("failed to marshal message to conn: %v", err))
			result <- server
			return
		}
		if _, err := conn.Write(encoding.Bytes()); err != nil {
			log.Error(fmt.Sprintf("unable to write encoded message to connection: %v", err))
			result <- server
			return
		}
		result <- nil
	default:
		log.Error("Unsupported connection information type.", "conn", server)
		result <- server
	}
}

func choosePath(ctx context.Context, local, remote *snet.Addr) *sd.PathReplyEntry {
	pathMgr := snet.DefNetwork.PathResolver()
	pathSet := pathMgr.Query(ctx, local.IA, remote.IA, sciond.PathReqFlags{})
	for _, p := range pathSet {
		return p.Entry
	}
	return nil
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
	reader := cbor.NewReader(conn)
	var msg message.Message
	if err := reader.Unmarshal(&msg); err != nil {
		errs := strings.Split(err.Error(), ": ")
		if errs[len(errs)-1] == "use of closed network connection" ||
			err.Error() == "failed to read tag: EOF" {
			log.Info("Connection has been closed", "conn", conn.RemoteAddr())
			conn.Close()
			serverError <- true
		} else {
			log.Warn("Was not able to decode received message", "error", err)
			serverError <- false
		}
		return
	}
	//Rainspub only accepts notification messages in response to published information.
	if n, ok := msg.Content[0].(*section.Notification); ok && n.Token == token {
		if handleResponse(conn, msg.Content[0].(*section.Notification)) {
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
func handleResponse(conn net.Conn, n *section.Notification) bool {
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
