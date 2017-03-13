//The switchboard listens for incoming connections from servers or clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"

	"bufio"

	"strings"

	"errors"

	"github.com/golang/groupcache/lru"
	log "github.com/inconshreveable/log15"
)

const (
	rootPEM = `
-----BEGIN CERTIFICATE-----
MIID5TCCAs2gAwIBAgIJAJGmPmx+xCpcMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD
VQQGEwJDSDEPMA0GA1UECAwGWnVyaWNoMQ8wDQYDVQQHDAZadXJpY2gxDDAKBgNV
BAoMA0VUSDEPMA0GA1UECwwGTmV0U2VjMQ8wDQYDVQQDDAZzZXJ2ZXIxJzAlBgkq
hkiG9w0BCQEWGGZlaGxtYWNoQHN0dWRlbnQuZXRoei5jaDAeFw0xNzAzMTMxMDE3
MTlaFw0yNzAzMTExMDE3MTlaMIGIMQswCQYDVQQGEwJDSDEPMA0GA1UECAwGWnVy
aWNoMQ8wDQYDVQQHDAZadXJpY2gxDDAKBgNVBAoMA0VUSDEPMA0GA1UECwwGTmV0
U2VjMQ8wDQYDVQQDDAZzZXJ2ZXIxJzAlBgkqhkiG9w0BCQEWGGZlaGxtYWNoQHN0
dWRlbnQuZXRoei5jaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANaI
rGRyjAKsj7Ma1xwXT7vlB1Bstr60GRQr/QKCr3EadhgXfX4u4SlCnoswVV8X8t9v
Ik8lxozfO/jYrJd/J2YG+cRHlm5dVR2t3cAe+AhhOyMi9tpBcGY9uizeD5sPyGqh
3ZF4XjqMQyN5N8OANNNCEs87zYfwVDzifR2tYpZdUMKjI0G7WpydSmywKjZq11VE
8rgd6vOGimLOLZaxS3yA+N2d8L9YAohBAKrhCUaDnqt5Yj092e3QP5hBuyjR+NSd
vCVX/fAMVMkUSD+QpLR8RYEK8ykHCZzWJaNO6vH41KAyZiE34H4rg05booADnF0B
gbDY2ClVV/iwYs0KgIkCAwEAAaNQME4wHQYDVR0OBBYEFAkWeBV9SFceJAxe6J/g
ZeC2fJeZMB8GA1UdIwQYMBaAFAkWeBV9SFceJAxe6J/gZeC2fJeZMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGSKwxsOau6GcQEF7La3aoVba3bRanQh
/EJVzSc4GECTgonMFnn3PfzOTTG4iL5FPyLZ9Hu3pJXwP7eyHwR9sGYvvepDhwXA
0syIuR282H06ByXwl8nIQRjRi1agISEZAyp1Y3iEkEjmCE1PUKAK4qzFvSTSdJJv
tBk5pNPDR/UJwH1kK375cpeFjSH4sw4yIz13fAfrOV2y5n7yN8/dj1pNse7V5vKo
thj2gY5vhK5JpSdRP5Tiwb6nju/zj8AxxVpWlX3I6PeQ+yCTPPVvIBCd1EiJwYyI
y+QQwhgbAkl8kkGwLh5q8TcgFeHzkHcc/nQQdoMRBBnGpjKZ44Egrpg=
-----END CERTIFICATE-----`
)

//TODO make an interface such that different cache implementation can be used in the future
var connCache = lru.New(int(Config.MaxConnections))
var serverConnInfo = getIPAddrandPort()
var roots *x509.CertPool

func init() {
	//TODO remove after we have proper starting procedure
	loadConfig()
	//init certificate
	roots = x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		log.Error("failed to parse root certificate")
		panic("failed to parse root certificate")
	}
	connCache.OnEvicted = func(key lru.Key, value interface{}) {
		if value, ok := value.(net.Conn); ok {
			value.Close()
		}
	}
	listen()
}

//TODO periodically send heartbeat to all server connections (store ConnInfo of servers in a different cache and look up writer in the active cache)

//SendTo sends the given message to the specified receiver.
//TODO replace string with RainsMessage
func SendTo(message string, receiver ConnInfo) {
	sendLog := log.New("Connection info", receiver)
	conn, ok := connCache.Get(creat4Tuple(receiver, serverConnInfo))
	if ok {
		//connection is cached
		if conn, ok := conn.(net.Conn); ok {
			conn.Write(frame(message))
			sendLog.Info("Send successful")
		} else {
			sendLog.Error("Cannot cast cache entry to net.Conn")
		}
	} else {
		//connection is not cached
		conn, err := creatConnection(receiver)
		if err != nil {
			sendLog.Warn("Could not establish connection", "error", err)
			return
		}
		conn.Write(frame(message))
		connCache.Add(creat4Tuple(receiver, serverConnInfo), conn)
		sendLog.Info("Send successful")
	}

}

func creatConnection(receiver ConnInfo) (net.Conn, error) {
	switch receiver.Type {
	case 1:
		return tls.Dial("tcp", receiver.IPAddrAndPort(), &tls.Config{RootCAs: roots})
	default:
		return nil, errors.New("No matching type found for Connection info")
	}
}

func creat4Tuple(client ConnInfo, server ConnInfo) string {
	sep := "_"
	switch client.Type {
	case 1:
		return client.IPAddr + sep + client.PortToString() + sep + server.IPAddr + sep + server.PortToString()
	default:
		log.Warn("No matching type found for client ConnInfo")
		return ""
	}
}

//TODO replace string with RainsMessage
func frame(message string) []byte {
	return []byte(message + "\n")
}

//deframe reads a framed message from r and returns the transformed message
//TODO replace string with RainsMessage
func deframe(frame []byte) string {
	return string(frame)
}

//listens for incoming TLS over TCP connections and calls handler
func listen() {
	addrAndport := serverConnInfo.IPAddrAndPort()
	srvLogger := log.New("addr", addrAndport)

	cer, err := tls.LoadX509KeyPair(Config.CertificateFile, Config.PrivateKeyFile)
	if err != nil {
		srvLogger.Error("Cannot load certificate", "error", err)
		return
	}

	srvLogger.Info("Start listener")
	listener, err := tls.Listen("tcp", addrAndport, &tls.Config{Certificates: []tls.Certificate{cer}})
	if err != nil {
		srvLogger.Error("Listener error on startup", "error", err)
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
		connCache.Add(creat4Tuple(connInfo, serverConnInfo), conn)
		go handleConnection(conn, connInfo)
	}
}

func handleConnection(conn net.Conn, client ConnInfo) {
	scan := bufio.NewScanner(bufio.NewReader(conn))
	for scan.Scan() {
		log.Info("Received a message", "conn", conn)
		msg := deframe(scan.Bytes())
		Deliver(msg, client)
	}
}

func parseRemoteAddr(s string) ConnInfo {
	addrAndPort := strings.Split(s, ":")
	port, _ := strconv.Atoi(addrAndPort[1])
	return ConnInfo{Type: 1, IPAddr: addrAndPort[0], Port: uint(port)}
}

//fetches HostAddr and port number form config file on which this server is listening to
func getIPAddrandPort() ConnInfo {
	if Config.ServerIPAddr == "" || Config.ServerPort == 0 {
		log.Error("Server's IPAddr or port are not in config")
	}
	return ConnInfo{Type: 1, IPAddr: Config.ServerIPAddr, Port: Config.ServerPort}
}
