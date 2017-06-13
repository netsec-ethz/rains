//The  incoming connections from servers or clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"crypto/tls"
	"errors"
	"net"
	"rains/rainslib"
	"rains/utils/protoParser"
	"time"

	log "github.com/inconshreveable/log15"
)

var connCache connectionCache

//InitSwitchboard initializes the switchboard
func initSwitchboard() error {
	var err error
	//init cache
	connCache, err = createConnectionCache(int(Config.MaxConnections))
	if err != nil {
		log.Error("Cannot create connCache", "error", err)
		return err
	}

	return nil
}

//sendTo sends the given message to the specified receiver.
func sendTo(message []byte, receiver rainslib.ConnInfo) {
	var framer rainslib.MsgFramer
	var err error
	framer = new(protoParser.ProtoParserAndFramer)
	addrPair := AddressPair{local: serverConnInfo, remote: receiver}
	conn, ok := connCache.Get(addrPair)
	if !ok {
		conn, err = createConnection(receiver)
		if err != nil {
			log.Warn("Could not establish connection", "error", err, "receiver", receiver)
			return
		}
		connCache.Add(addrPair, conn)
	}
	framer.InitStreams(nil, conn)
	err = framer.Frame(message)
	if err != nil {
		log.Error("Was not able to frame and/or send the message", "Error", err, "connection", conn, "receiver", receiver)
		return
	}
	log.Debug("Send successful", "receiver", receiver)
}

//createConnection establishes a connection based on the type and data of the ConnInfo
func createConnection(receiver rainslib.ConnInfo) (net.Conn, error) {
	switch receiver.Type {
	case rainslib.TCP:
		dialer := &net.Dialer{
			KeepAlive: Config.KeepAlivePeriod,
		}
		return tls.DialWithDialer(dialer, receiver.TCPAddr.Network(), receiver.String(), &tls.Config{RootCAs: roots})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

//Listen listens for incoming TLS over TCP connections and calls handler
func Listen() {
	srvLogger := log.New("addr", serverConnInfo.String())

	cert, err := tls.LoadX509KeyPair(Config.TLSCertificateFile, Config.TLSPrivateKeyFile)
	if err != nil {
		srvLogger.Warn("Path to CertificateFile or privateKeyFile might be invalid. Default values are used", "CertPath", Config.TLSCertificateFile,
			"KeyPath", Config.TLSPrivateKeyFile, "error", err)
		cert, err = tls.LoadX509KeyPair(defaultConfig.TLSCertificateFile, defaultConfig.TLSPrivateKeyFile)
		if err != nil {
			srvLogger.Error("Cannot load certificate", "error", err)
			return
		}
	}

	srvLogger.Info("Start listener")
	switch serverConnInfo.Type {
	case rainslib.TCP:
		listener, err := tls.Listen("tcp", serverConnInfo.String(), &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			srvLogger.Error("Listener error on startup", "error", err)
			return
		}
		defer listener.Close()
		defer srvLogger.Info("Shutdown listener")
		for {
			conn, err := listener.Accept()
			if err != nil {
				srvLogger.Error("error", err)
				continue
			}
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				connInfo := rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr}
				connCache.Add(AddressPair{local: serverConnInfo, remote: connInfo}, conn)
				go handleConnection(conn, connInfo)
			} else {
				log.Warn("Type assertion failed. Expected *net.TCPAddr", "addr", conn.RemoteAddr())
			}
		}
	default:
		log.Warn("Unsupported Network address type.")
	}
}

//handleConnection passes all incoming messages to the inbox which processes them.
func handleConnection(conn net.Conn, client rainslib.ConnInfo) {
	var framer rainslib.MsgFramer
	framer = new(protoParser.ProtoParserAndFramer)
	framer.InitStreams(conn, nil)
	for framer.DeFrame() {
		log.Info("Received a message", "client", client)
		deliver(framer.Data(), client)
		conn.SetDeadline(time.Now().Add(Config.TCPTimeout))
	}
	//TODO CFE should we be able to remove this connection from the connCache?
}
