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
	"github.com/netsec-ethz/rains/internal/pkg/connection/scion"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/scionproto/scion/go/lib/snet"
)

//sendTo sends message to the specified receiver with retries
func (s *Server) sendTo(msg message.Message, receiver net.Addr, retries,
	backoffMilliSeconds int) (err error) {

	// In any case we add the capabilities of this server to the message.
	msg.Capabilities = []message.Capability{message.Capability(s.capabilityHash)}
	encodedMsg := new(bytes.Buffer)
	if err := cbor.NewWriter(encodedMsg).Marshal(&msg); err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	// Try to send the message, with given number of retries
	backoff := time.Duration(backoffMilliSeconds) * time.Millisecond
	if err := s.sendToTry(encodedMsg.Bytes(), receiver); err == nil {
		return nil
	}
	for i := 1; i < retries; i++ {
		time.Sleep(backoff)
		backoff *= 2
		if err := s.sendToTry(encodedMsg.Bytes(), receiver); err == nil {
			return nil
		}
	}
	log.Error("Was not able to send the message. No retries left.", "receiver", receiver)
	return errors.New("Was not able to send the mesage. No retries left")
}

//sendToTry sends message to the specified receiver.
func (s *Server) sendToTry(encodedMsg []byte, receiver net.Addr) (err error) {
	if s.packetConn != nil {
		if _, err := s.packetConn.WriteTo(encodedMsg, receiver); err != nil {
			return fmt.Errorf("unable to send message: %v", err)
		}
		return nil
	} else {
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
			go s.handleConnection(conn, receiver)
			conns = []net.Conn{conn}
		}
		for _, conn := range conns {
			if _, err := conn.Write(encodedMsg); err != nil {
				s.caches.ConnCache.CloseAndRemoveConnection(conn)
				log.Warn("Was not able to send encoded message")
			} else {
				log.Debug("Send successful", "receiver", receiver)
				return nil
			}
		}
		return errors.New("unable to send message on any connection")
	}
}

func (s *Server) sendToRecursiveResolver(msg message.Message) {
	for _, sec := range msg.Content {
		if q, ok := sec.(*query.Name); ok {
			go s.resolver.ServerLookup(q, s.Addr(), msg.Token)
		}
	}
}

//createConnection establishes a connection with receiver
func createConnection(receiver net.Addr, keepAlive time.Duration, pool *x509.CertPool) (net.Conn, error) {
	switch receiver.(type) {
	case *net.TCPAddr:
		dialer := &net.Dialer{
			KeepAlive: keepAlive,
		}
		return tls.DialWithDialer(dialer, receiver.Network(), receiver.String(), &tls.Config{RootCAs: pool, InsecureSkipVerify: true})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

//Listen listens for incoming connections and creates a go routine for each connection.
func (s *Server) listen(id string) {
	srvLogger := log.New("id", id, "addr", s.Addr().String())
	switch s.config.ServerAddress.Type {
	case connection.TCP:
		srvLogger.Info("Start TCP listener")
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{s.tlsCert}, InsecureSkipVerify: true}
		listener, err := tls.Listen(s.Addr().Network(),
			s.config.ServerAddress.Addr.String(), tlsConfig)
		if err != nil {
			srvLogger.Error("Listener error on startup", "error", err)
			return
		}
		defer listener.Close()
		defer srvLogger.Info("TCP Shutdown listener")
		for {
			select {
			case <-s.shutdown:
				// break out of the loop when receiving shutdown
				srvLogger.Info("Received shutdown signal from TCP")
				return
			default:
			}
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
				go s.handleConnection(conn, tcpAddr)
			} else {
				log.Warn("Type assertion failed. Expected *net.TCPAddr", "addr", conn.RemoteAddr())
			}
		}
	case connection.SCION:
		addr, ok := s.config.ServerAddress.Addr.(*snet.UDPAddr)
		if !ok {
			log.Warn(fmt.Sprintf("Type assertion failed. Expected *connection.SCIONAddr, got %T", addr))
			return
		}
		conn, err := scion.Listen(addr.Host)
		srvLogger.Info(fmt.Sprintf("Started SCION listener on %v", addr), "id", id)
		if err != nil {
			log.Warn("failed to ListenSCION", "err", err)
			return
		}
		defer conn.Close()
		defer srvLogger.Info("SCION Shutdown listener", "id", id)
		s.packetConn = conn
		for {
			select {
			case <-s.shutdown:
				// break out of the loop when receiving shutdown
				srvLogger.Info("Received shutdown signal from SCION")
				return
			default:
			}
			buf := make([]byte, connection.MaxUDPPacketBytes)
			n, addr, err := s.packetConn.ReadFrom(buf)
			if err != nil {
				log.Warn("Failed to ReadFrom", "err", err)
				continue
			}
			data := buf[:n]
			// Note: We cannot use handleConnection because UDP is connectionless and we have to
			// manually stick the remote endpoint address in the handler.
			var msg message.Message
			if err := cbor.NewReader(bytes.NewReader(data)).Unmarshal(&msg); err != nil {
				log.Warn("failed to unmarshal CBOR", "err", err)
				continue
			}
			deliver(&msg, addr,
				s.queues.Prio, s.queues.Normal, s.queues.Notify, s.caches.PendingKeys)
		}
	default:
		log.Warn("Unsupported Network address type.")
	}
}

//handleConnection deframes all incoming messages on conn and passes them to the inbox along with the dstAddr
func (s *Server) handleConnection(conn net.Conn, dstAddr net.Addr) {
	log.Info("New connection", "serverAddr", s.Addr(), "conn", dstAddr)
	reader := cbor.NewReader(conn)
	for {
		var msg message.Message
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
		deliver(&msg, conn.RemoteAddr(),
			s.queues.Prio, s.queues.Normal, s.queues.Notify, s.caches.PendingKeys)
	}
	s.caches.ConnCache.CloseAndRemoveConnection(conn)
}

//isIPBlacklisted returns true if addr is blacklisted
func isIPBlacklisted(addr net.Addr) bool {
	return false
}
