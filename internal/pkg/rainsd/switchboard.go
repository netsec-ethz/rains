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

	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"

	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
)

const (
	dispatcherPath = "/run/shm/dispatcher/default.sock"
)

//sendTo sends message to the specified receiver.
func (s *Server) sendTo(msg message.Message, receiver connection.Info, retries,
	backoffMilliSeconds int) (err error) {
	// TODO: Implement caching and retries for SCION connections.
	if receiver.Type == connection.SCION {
		writer := cbor.NewWriter(*receiver.SCIONStream)
		if err := writer.Marshal(&msg); err != nil {
			log.Warn(fmt.Sprintf("failed to marshal message to conn: %v", err))
			return err
		}
	}
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
		writer := cbor.NewWriter(conn)
		if err := writer.Marshal(&msg); err != nil {
			log.Warn(fmt.Sprintf("failed to marshal message to conn: %v", err))
			s.caches.ConnCache.CloseAndRemoveConnection(conn)
			continue
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

// defaultSciondPath returns the well known location of the scion socket.
func defaultSciondPath(ia addr.IA) string {
	return fmt.Sprintf("/run/shm/sciond/sd%s.sock", ia.FileFmt(false))
}

// initNetwork configures the SCION subsystem for listening on a server socket via squic.
func initNetwork(addr *snet.Addr) error {
	if err := snet.Init(addr.IA, defaultSciondPath(addr.IA), dispatcherPath); err != nil {
		return fmt.Errorf("failed to initialize snet: %v", err)
	}
	log.Debug("Sucessfully initialized snet")
	if err := squic.Init("", ""); err != nil {
		return fmt.Errorf("failed to initialize squic: %v", err)
	}
	log.Debug("QUIC/SCION successfully initialized")
	return nil
}

//Listen listens for incoming connections and creates a go routine for each connection.
func (s *Server) listen() {
	srvLogger := log.New("addr", s.config.ServerAddress.String())
	switch s.config.ServerAddress.Type {
	case connection.SCION:
		srvLogger.Info("Starting SCION listener")
		localAddr := s.config.ServerAddress.SCIONAddr
		if err := initNetwork(localAddr); err != nil {
			srvLogger.Error("Failed to initNetwork", "err", err)
			return
		}
		qsock, err := squic.ListenSCION(nil, localAddr)
		if err != nil {
			srvLogger.Error("Failed to ListenScion", "err", err)
			return
		}
		for {
			qsess, err := qsock.Accept()
			if err != nil {
				srvLogger.Warn("Failed to accept connection", "err", err)
				continue
			}
			go s.handleConnectionSCION(qsess, connection.Info{Type: connection.SCION})
		}
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
	case connection.Chan:
		s.channel.Channel = make(chan connection.Message, 100)
		s.handleChannel()
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
		case msg := <-s.channel.Channel:
			s.caches.ConnCache.AddConnection(msg.Sender)
			m := &message.Message{}
			reader := cbor.NewReader(bytes.NewBuffer(msg.Msg))
			if err := reader.Unmarshal(m); err != nil {
				log.Warn(fmt.Sprintf("failed to unmarshal msg recv over channel: %v", err))
				continue
			}
			deliver(m, connection.Info{Type: connection.Chan, ChanAddr: msg.Sender.Addr},
				s.queues.Prio, s.queues.Normal, s.queues.Notify, s.caches.PendingKeys)
		}
	}
}

func (s *Server) handleConnectionSCION(qsess quic.Session, ci connection.Info) {
	qstr, err := qsess.AcceptStream()
	if err != nil {
		log.Warn("failed to accept quic stream from client", "err", err)
	}
	ci.SCIONStream = &qstr
	var msg message.Message
	reader := cbor.NewReader(qstr)
	for {
		if err := reader.Unmarshal(&msg); err != nil {
			log.Warn("failed to read from quic stream", "err", err)
			return
		}
		deliver(&msg, ci, s.queues.Prio, s.queues.Normal, s.queues.Notify, s.caches.PendingKeys)
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
