//The switchboard listens for incoming connections from servers or clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
)

//TODO CFE this uses MPL 2.0 licence, write it ourself (Brian has sample code)
var connCache Cache
var serverConnInfo ConnInfo
var roots *x509.CertPool
var framer scanner

//TODO CFE what should the name of this interface be?
type scanner interface {
	//Frame takes a message and adds a frame to it
	Frame(msg []byte) ([]byte, error)

	//Deframe extracts the next frame from a stream.
	//It blocks until it encounters the delimiter.
	//It returns false when the stream is closed.
	//The data is available through Data
	Deframe() bool

	//Data contains the frame read from the stream by Deframe
	Data() []byte
}

type newLineFramer struct {
	Scanner   *bufio.Scanner
	firstCall bool
}

func (f newLineFramer) Frame(msg []byte) ([]byte, error) {
	return append(msg, "\n"...), nil
}

func (f *newLineFramer) Deframe() bool {
	if f.firstCall {
		f.Scanner.Split(bufio.ScanLines)
		f.firstCall = false
	}
	return f.Scanner.Scan()
}

func (f newLineFramer) Data() []byte {
	return f.Scanner.Bytes()
}

func init() {
	//TODO CFE remove after we have proper starting procedure.
	//TODO Do not call panic but instead return error or if we are in main() log error and exit
	var err error
	//init config
	loadConfig()
	serverConnInfo, err = getIPAddrandPort()
	if err != nil {
		log.Error("error", err)
		panic(err)
	}
	//init cache
	connCache = &LRUCache{}
	err = connCache.NewWithEvict(
		func(key interface{}, value interface{}) {
			if value, ok := value.(net.Conn); ok {
				value.Close()
			}
		}, int(Config.MaxConnections))
	if err != nil {
		log.Error("Cannot create connCache", "error", err)
		panic(err)
	}
	//init certificate
	roots = x509.NewCertPool()
	file, err := ioutil.ReadFile(Config.CertificateFile)
	if err != nil {
		log.Error("error", err)
	}
	ok := roots.AppendCertsFromPEM(file)
	if !ok {
		log.Error("failed to parse root certificate")
		panic("failed to parse root certificate")
	}
	//init framer
	framer = &newLineFramer{}
	listen()
}

//SendTo sends the given message to the specified receiver.
//TODO CFE replace string with RainsMessage
func SendTo(message []byte, receiver ConnInfo) {
	sendLog := log.New("Connection info", receiver)
	conn, ok := connCache.Get(create4Tuple(receiver, serverConnInfo))
	if ok {
		//connection is cached
		if conn, ok := conn.(net.Conn); ok {
			frame, err := framer.Frame(message)
			if err != nil {
				log.Error("Error", err)
				return
			}
			conn.Write(frame)
			connCache.Add(create4Tuple(receiver, serverConnInfo), conn)
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
		connCache.Add(create4Tuple(receiver, serverConnInfo), conn)
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
		return tls.DialWithDialer(dialer, "tcp", receiver.IPAddrAndPort(), &tls.Config{RootCAs: roots})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

//create4Tuple returns a string containing the 4 tuple of the connection
func create4Tuple(client ConnInfo, server ConnInfo) string {
	switch client.Type {
	case TCP:
		return fmt.Sprintf("%s_%d_%s_%d", client.IPAddr, client.Port, server.IPAddr, server.Port)
	default:
		log.Warn("No matching type found for client ConnInfo")
		return ""
	}
}

//listens for incoming TLS over TCP connections and calls handler
func listen() {
	addrAndport := serverConnInfo.IPAddrAndPort()
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
		connCache.Add(create4Tuple(connInfo, serverConnInfo), conn)
		go handleConnection(conn, connInfo)
	}
}

//handleConnection passes all incoming messages to the inbox which processes them.
func handleConnection(conn net.Conn, client ConnInfo) {
	//TODO CFE replace newLineFramer when we have a CBOR framer!
	scan := newLineFramer{Scanner: bufio.NewScanner(bufio.NewReader(conn)), firstCall: true}
	for scan.Deframe() {
		log.Info("Received a message", "client", client)
		Deliver(scan.Data(), client)
		conn.SetDeadline(time.Now().Add(Config.TCPTimeout))
	}
}

//parseRemoteAddr translates an address obtained from net.Conn.RemoteAddr() to the internal representation ConnInfo
func parseRemoteAddr(s string) ConnInfo {
	addrAndPort := strings.Split(s, ":")
	port, _ := strconv.Atoi(addrAndPort[1])
	return ConnInfo{Type: TCP, IPAddr: addrAndPort[0], Port: uint16(port)}
}

//getIPAddrandPort fetches HostAddr and port number from config file on which this server is listening to
func getIPAddrandPort() (ConnInfo, error) {
	return ConnInfo{Type: TCP, IPAddr: Config.ServerIPAddr, Port: Config.ServerPort}, nil
}
