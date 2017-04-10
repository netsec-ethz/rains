//The  incoming connections from servers or clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
)

//TODO CFE this uses MPL 2.0 licence, write it ourself (Brian has sample code)
var connCache connectionCache
var framer scanner

//InitSwitchboard initializes the switchboard
func initSwitchboard() error {
	var err error
	//init cache
	connCache, err = createConnectionCache(int(Config.MaxConnections))
	if err != nil {
		log.Error("Cannot create connCache", "error", err)
		return err
	}
	//init framer
	framer = &newLineFramer{}
	return nil
}

//sendTo sends the given message to the specified receiver.
func sendTo(message []byte, receiver ConnInfo) {
	sendLog := log.New("Connection info", receiver)
	addrPair := AddressPair{local: serverConnInfo, remote: receiver}
	conn, ok := connCache.Get(addrPair)
	if ok {
		//connection is cached
		if conn, ok := conn.(net.Conn); ok {
			frame, err := framer.Frame(message)
			if err != nil {
				log.Error("Error", err)
				return
			}
			conn.Write(frame)
			connCache.Add(addrPair, conn)
			sendLog.Info("Send successful (cached)")
		} else {
			sendLog.Error("Cannot cast cache entry to net.Conn")
		}
	} else {
		//connection is not cached
		conn, err := createConnection(receiver)
		if err != nil {
			sendLog.Warn("Could not establish connection", "error", err)
			return
		}
		frame, err := framer.Frame(message)
		if err != nil {
			log.Error("Error", err)
			return
		}
		conn.Write(frame)
		connCache.Add(addrPair, conn)
		sendLog.Info("Send successful (new connection)")
	}

}

//createConnection establishes a connection based on the type and data of the ConnInfo
func createConnection(receiver ConnInfo) (net.Conn, error) {
	switch receiver.Type {
	case TCP:
		dialer := &net.Dialer{
			KeepAlive: Config.KeepAlivePeriod,
		}
		return tls.DialWithDialer(dialer, "tcp", receiver.String(), &tls.Config{RootCAs: roots})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

//Listen listens for incoming TLS over TCP connections and calls handler
func Listen() {
	addrAndport := serverConnInfo.String()
	srvLogger := log.New("addr", addrAndport)

	cert, err := tls.LoadX509KeyPair(Config.CertificateFile, Config.PrivateKeyFile)
	if err != nil {
		srvLogger.Warn("Path to CertificateFile or privateKeyFile might be invalid. Default values are used", "CertPath", Config.CertificateFile, "KeyPath", Config.PrivateKeyFile)
		cert, err = tls.LoadX509KeyPair(defaultConfig.CertificateFile, defaultConfig.PrivateKeyFile)
		if err != nil {
			srvLogger.Error("Cannot load certificate", "error", err)
			return
		}
	}

	srvLogger.Info("Start listener")
	listener, err := tls.Listen("tcp", addrAndport, &tls.Config{Certificates: []tls.Certificate{cert}})
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
		connInfo := parseRemoteAddr(conn.RemoteAddr().String())
		connCache.Add(AddressPair{local: serverConnInfo, remote: connInfo}, conn)
		go handleConnection(conn, connInfo)
	}
}

//handleConnection passes all incoming messages to the inbox which processes them.
func handleConnection(conn net.Conn, client ConnInfo) {
	//TODO CFE replace newLineFramer when we have a CBOR framer!
	scan := newLineFramer{Scanner: bufio.NewScanner(bufio.NewReader(conn)), firstCall: true}
	for scan.Deframe() {
		log.Info("Received a message", "client", client)
		deliver(scan.Data(), client)
		conn.SetDeadline(time.Now().Add(Config.TCPTimeout))
	}
}

//parseRemoteAddr translates an address obtained from net.Conn.RemoteAddr() to the internal representation ConnInfo
func parseRemoteAddr(s string) ConnInfo {
	addrAndPort := strings.Split(s, ":")
	port, _ := strconv.Atoi(addrAndPort[1])
	return ConnInfo{Type: TCP, IPAddr: net.ParseIP(addrAndPort[0]), Port: uint16(port)}
}
