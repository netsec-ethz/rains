//The switchboard handles incoming connections from servers and clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
)

//sendTo sends message to the specified receiver.
func (s *Server) sendTo(msg message.Message, receiver connection.Info, retries,
	backoffMilliSeconds int) (err error) {
	conns, ok := s.caches.ConnCache.GetConnection(receiver)
	if !ok {
		conn, err := createConnection(receiver, s.config.KeepAlivePeriod, s.certPool)
		//add connection to cache
		conns = append(conns, conn)
		if err != nil {
			log.Warn("Could not establish connection", "error", err, "receiver", receiver)
			return err
		}
		s.caches.ConnCache.AddConnection(conn)
		//handle connection
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			go s.handleConnection(conn, connection.Info{Type: connection.TCP, TCPAddr: tcpAddr})
		} else {
			log.Warn("Type assertion failed. Expected *net.TCPAddr", "addr", conn.RemoteAddr())
		}
		//add capabilities to message
		msg.Capabilities = []message.Capability{message.Capability(s.capabilityHash)}
	}
	for _, conn := range conns {
		log.Debug("Send message", "dst", conn.RemoteAddr(), "content", msg)
		//FIXME CFE, cannot write to conn directly because if conn is a channel it does not work.
		//This is because the cbor library writes multiple times to the connection, but the channel
		//receiver only listens for one message. Is there a way for the receiver to determine when a
		//message is processed and then stop listening?
		encoding := new(bytes.Buffer)
		if err := cbor.NewWriter(encoding).Marshal(&msg); err != nil {
			log.Warn(fmt.Sprintf("failed to marshal message to conn: %v", err))
			s.caches.ConnCache.CloseAndRemoveConnection(conn)
			continue
		}
		if _, err := conn.Write(encoding.Bytes()); err != nil {
			log.Warn("Was not able to send encoded message")
		}
		log.Debug("Send successful", "receiver", receiver)
		return nil
	}
	if retries > 0 {
		time.Sleep(time.Duration(backoffMilliSeconds) * time.Millisecond)
		return s.sendTo(msg, receiver, retries-1, 2*backoffMilliSeconds)
	}
	log.Error("Was not able to send the message. No retries left.", "receiver", receiver)
	return errors.New("Was not able to send the mesage. No retries left")
}

func (s *Server) sendToRecursiveResolver(msg message.Message) {
	encoding := new(bytes.Buffer)
	if err := cbor.NewWriter(encoding).Marshal(&msg); err != nil {
		log.Warn(fmt.Sprintf("failed to marshal message to conn: %v", err))
	}
	message := connection.Message{
		Msg:    encoding.Bytes(),
		Sender: s.inputChannel,
	}
	s.sendToRecResolver(message)
	log.Debug("Send successfully to recursive resolver")
}

//createConnection establishes a connection with receiver
func createConnection(receiver connection.Info, keepAlive time.Duration, pool *x509.CertPool) (net.Conn, error) {
	switch receiver.Type {
	case connection.TCP:
		dialer := &net.Dialer{
			KeepAlive: keepAlive,
		}
		return tls.DialWithDialer(dialer, receiver.TCPAddr.Network(), receiver.String(), &tls.Config{RootCAs: pool, InsecureSkipVerify: true})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

//Listen listens for incoming connections and creates a go routine for each connection.
func (s *Server) listen() {
	srvLogger := log.New("addr", s.config.ServerAddress.String())
	//always listen on channel
	go s.handleChannel()
	switch s.config.ServerAddress.Type {
	case connection.TCP:
		srvLogger.Info("Start TCP listener")
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{s.tlsCert}, InsecureSkipVerify: true}
		listener, err := tls.Listen(s.config.ServerAddress.TCPAddr.Network(),
			s.config.ServerAddress.String(), tlsConfig)
		if err != nil {
			srvLogger.Error("Listener error on startup", "error", err)
			return
		}
		defer listener.Close()
		defer srvLogger.Info("Shutdown listener")
		for {
			conn, err := listener.Accept()
			if err != nil {
				srvLogger.Error("listener could not accept connection", "error", err)
				continue
			}
			if isIPBlacklisted(conn.RemoteAddr()) {
				continue
			}
			s.caches.ConnCache.AddConnection(conn)
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				go s.handleConnection(conn, connection.Info{Type: connection.TCP, TCPAddr: tcpAddr})
			} else {
				log.Warn("Type assertion failed. Expected *net.TCPAddr", "addr", conn.RemoteAddr())
			}
		}
	default:
		log.Warn("Unsupported Network address type.")
	}
}

//handleChannel handles incoming messages over the channel
func (s *Server) handleChannel() {
	for {
		select {
		case <-s.shutdown:
			return
		case msg := <-s.inputChannel.RemoteChan:
			msg.Sender.LocalChan = s.inputChannel.RemoteChan
			msg.Sender.SetLocalAddr(s.inputChannel.RemoteAddr().(connection.ChannelAddr))
			s.caches.ConnCache.AddConnection(msg.Sender)
			m := &message.Message{}
			reader := cbor.NewReader(bytes.NewBuffer(msg.Msg))
			if err := reader.Unmarshal(m); err != nil {
				log.Warn(fmt.Sprintf("failed to unmarshal msg recv over channel: %v", err))
				continue
			}
			deliver(m, connection.Info{Type: connection.Chan, ChanAddr: msg.Sender.RemoteAddr().(connection.ChannelAddr)},
				s.queues.Prio, s.queues.Normal, s.queues.Notify, s.caches.PendingKeys)
		}
	}
}

//handleConnection deframes all incoming messages on conn and passes them to the inbox along with the dstAddr
func (s *Server) handleConnection(conn net.Conn, dstAddr connection.Info) {
	log.Info("Handling connection", "conn", dstAddr)
	var msg message.Message
	reader := cbor.NewReader(conn)
	for {
		select {
		case <-s.shutdown:
			return
		default:
		}
		//FIXME CFE how to check efficiently that message is not too large?
		if err := reader.Unmarshal(&msg); err != nil {
			if err.Error() == "failed to read tag: EOF" {
				log.Info("Connection has been closed", "conn", dstAddr)
			} else {
				log.Warn(fmt.Sprintf("failed to read from client: %v", err))
			}
			break
		}
		deliver(&msg, connection.Info{Type: connection.TCP, TCPAddr: conn.RemoteAddr().(*net.TCPAddr)},
			s.queues.Prio, s.queues.Normal, s.queues.Notify, s.caches.PendingKeys)
	}
	s.caches.ConnCache.CloseAndRemoveConnection(conn)
}

//isIPBlacklisted returns true if addr is blacklisted
func isIPBlacklisted(addr net.Addr) bool {
	log.Warn("TODO CFE ip blacklist not yet implemented")
	return false
}
