//The switchboard listens for incoming connections from servers or clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"strconv"

	"bufio"

	"strings"

	"github.com/golang/groupcache/lru"
)

const (
	configPath = "config"
	rootPEM    = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`
)

//TODO make an interface such that different cache implementation can be used in the future
var connCache = lru.New(1000)
var serverConnInfo = getIPAddrandPort()
var roots *x509.CertPool

func init() {
	//init certificate
	roots = x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		log.Fatal("failed to parse root certificate")
	}
	listen()
}

//TODO periodically send heartbeat to all server connections (store ConnInfo of servers in a different cache and look up writer in the active cache)

//SendTo sends the given message to the specified receiver.
//TODO replace string with RainsMessage
func SendTo(message string, receiver ConnInfo) {
	conn, ok := connCache.Get(creat4Tuple(receiver, serverConnInfo))
	port := strconv.Itoa(int(receiver.Port))
	if !ok {
		conn, err := tls.Dial("tcp", receiver.Host.IPAddr+":"+port, &tls.Config{RootCAs: roots})
		if err != nil {
			log.Println("Could not connect to" + receiver.Host.IPAddr + ":" + port)
			return
		}
		conn.Write(frame(message))
		connCache.Add(creat4Tuple(receiver, serverConnInfo), conn)
		log.Println("Successfully connect to" + receiver.Host.IPAddr + ":" + port)
		return
	}
	if conn, ok := conn.(net.Conn); ok {
		conn.Write(frame(message))
		log.Println("Successfully connect to" + receiver.Host.IPAddr + ":" + port)
		return
	}
	log.Println("Could not connect to" + receiver.Host.IPAddr + ":" + port)
}

func creat4Tuple(client ConnInfo, server ConnInfo) string {
	sep := "_"
	return client.Host.IPAddr + sep + strconv.Itoa(int(client.Port)) + sep + server.Host.IPAddr + sep + strconv.Itoa(int(server.Port))
}

//TODO replace string with RainsMessage
func frame(message string) []byte {
	return []byte(message + "\n")
}

//deframe reads a framed message from r and returns the transformed message
//TODO replace string with RainsMessage
func deframe(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	scanner.Scan()
	return scanner.Text()
}

//listens for incoming connections and calls handler
func listen() {
	addrAndport := serverConnInfo.Host.IPAddr + ":" + strconv.Itoa(int(serverConnInfo.Port))
	log.Println("Start listening on addr and port: " + addrAndport)

	listener, err := tls.Listen("tcp", addrAndport, &tls.Config{RootCAs: roots})
	if err != nil {
		log.Fatal("Cannot listen on addr and port:" + addrAndport)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		connCache.Add(creat4Tuple(parseRemoteAddr(conn.RemoteAddr().String()), serverConnInfo), conn)
		//TODO close connection if it gets removed. -> onevicted
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		Deliver(msg, parseRemoteAddr(conn.RemoteAddr().String()))
	}
}

func parseRemoteAddr(s string) ConnInfo {
	addrAndPort := strings.Split(s, ":")
	host := HostAddr{addrAndPort[0]}
	port, _ := strconv.Atoi(addrAndPort[1])
	return ConnInfo{Host: host, Port: uint(port)}
}

//fetches HostAddr and port number form config file on which this server is listening to
func getIPAddrandPort() ConnInfo {
	if Config.ServerIPAddr == "" || Config.ServerPort == 0 {
		log.Fatal("Server's IPAddr or port are not in config")
	}
	host := HostAddr{Config.ServerIPAddr}
	return ConnInfo{Host: host, Port: Config.ServerPort}
}
