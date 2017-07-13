//The switchboard handles incoming connections from servers and clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"

	log "github.com/inconshreveable/log15"
)

//connCache stores connections of this server. It is not guaranteed that a returned connection is still active.
var connCache connectionCache

var cert tls.Certificate

//InitSwitchboard initializes the switchboard
func initSwitchboard() error {
	var err error
	//init cache
	connCache, err = createConnectionCache(Config.MaxConnections)
	if err != nil {
		log.Error("Cannot create connCache", "error", err)
		return err
	}
	cert, err = tls.LoadX509KeyPair(Config.TLSCertificateFile, Config.TLSPrivateKeyFile)
	if err != nil {
		log.Error("Cannot load certificate. Path to CertificateFile or privateKeyFile might be invalid.", "CertPath", Config.TLSCertificateFile,
			"KeyPath", Config.TLSPrivateKeyFile, "error", err)
		return err
	}
	return nil
}

//sendTo sends message to the specified receiver.
func sendTo(message []byte, receiver rainslib.ConnInfo, retries, backoffMilliSeconds int) (err error) {
	var framer rainslib.MsgFramer

	conns, ok := connCache.Get(receiver)
	if !ok {
		conn, err := createConnection(receiver)
		//add connection to cache
		conns = append(conns, conn)
		if err != nil {
			log.Warn("Could not establish connection", "error", err, "receiver", receiver)
			return err
		}
		connCache.Add(conn)
		//handle connection
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			go handleConnection(conn, rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr})
		} else {
			log.Warn("Type assertion failed. Expected *net.TCPAddr", "addr", conn.RemoteAddr())
		}
	}
	framer = new(protoParser.ProtoParserAndFramer)
	for _, conn := range conns {
		framer.InitStreams(nil, conn)
		err = framer.Frame(message)
		if err != nil {
			log.Warn("Was not able to frame or send the message", "Error", err, "connections", conns, "receiver", receiver)
			connCache.Delete(conn)
			continue
		}
		log.Debug("Send successful", "receiver", receiver)
		return nil
	}
	if retries > 0 {
		time.Sleep(time.Duration(backoffMilliSeconds) * time.Millisecond)
		return sendTo(message, receiver, retries-1, 2*backoffMilliSeconds)
	}
	log.Error("Was not able to send the message. No retries left.", "receiver", receiver)
	return errors.New("Was not able to send the mesage. No retries left")
}

//createConnection establishes a connection with receiver
func createConnection(receiver rainslib.ConnInfo) (net.Conn, error) {
	switch receiver.Type {
	case rainslib.TCP:
		dialer := &net.Dialer{
			KeepAlive: Config.KeepAlivePeriod,
		}
		return tls.DialWithDialer(dialer, receiver.TCPAddr.Network(), receiver.String(), &tls.Config{RootCAs: roots, InsecureSkipVerify: true})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

//Listen listens for incoming connections and creates a go routine for each connection.
func Listen() {
	srvLogger := log.New("addr", serverConnInfo.String())

	switch serverConnInfo.Type {
	case rainslib.TCP:
		srvLogger.Info("Start TCP listener")
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		listener, err := tls.Listen(serverConnInfo.TCPAddr.Network(), serverConnInfo.String(), tlsConfig)
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
			connCache.Add(conn)
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				go handleConnection(conn, rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr})
			} else {
				log.Warn("Type assertion failed. Expected *net.TCPAddr", "addr", conn.RemoteAddr())
			}
		}
	default:
		log.Warn("Unsupported Network address type.")
	}
}

//handleConnection deframes all incoming messages on conn and passes them to the inbox along with the dstAddr
func handleConnection(conn net.Conn, dstAddr rainslib.ConnInfo) {
	var framer rainslib.MsgFramer
	framer = new(protoParser.ProtoParserAndFramer)
	framer.InitStreams(conn, nil)
	for framer.DeFrame() {
		log.Info("Received a message", "sender", dstAddr)
		deliver(framer.Data(), dstAddr)
		conn.SetDeadline(time.Now().Add(Config.TCPTimeout))
	}
	connCache.Delete(conn)
	conn.Close()
	log.Debug("connection removed from cache", "remoteAddr", conn.RemoteAddr())
}
