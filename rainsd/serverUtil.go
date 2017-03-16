package rainsd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"rains/rainslib"
	"strconv"
	"time"
)

const (
	configPath = "config/server.conf"
)

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	//switchboard
	ServerIPAddr    string
	ServerPort      uint16
	MaxConnections  uint
	KeepAlivePeriod time.Duration
	TCPTimeout      time.Duration
	CertificateFile string
	PrivateKeyFile  string

	//inbox
	PrioBufferSize   uint
	NormalBufferSize uint
	PrioWorkerSize   uint
	NormalWorkerSize uint

	//verify
	ZoneKeyCacheSize          uint
	PendingSignatureCacheSize uint

	//engine
	AssertionCacheSize    uint
	PendingQueryCacheSize uint

	//notification
	CapabilitiesCacheSize uint
}

//DefaultConfig is a rainsdConfig object containing default values
var defaultConfig = rainsdConfig{ServerIPAddr: "127.0.0.1", ServerPort: 5022, MaxConnections: 1000, KeepAlivePeriod: time.Minute, TCPTimeout: 5 * time.Minute,
	CertificateFile: "config/server.crt", PrivateKeyFile: "config/server.key", PrioBufferSize: 1000, NormalBufferSize: 100000, PrioWorkerSize: 2, NormalWorkerSize: 10,
	ZoneKeyCacheSize: 1000, PendingSignatureCacheSize: 1000, AssertionCacheSize: 10000, PendingQueryCacheSize: 100, CapabilitiesCacheSize: 100}

//ProtocolType enumerates protocol types
type ProtocolType int

const (
	TCP ProtocolType = iota
)

//ConnInfo contains address information about one actor of a connection of the declared type
//type 1 contains IPAddr and Port information
type ConnInfo struct {
	Type   ProtocolType
	IPAddr string
	Port   uint16
}

//MsgSender contains the message and connection infos about the sender
type MsgSender struct {
	Sender ConnInfo
	Msg    rainslib.RainsMessage
}

//IPAddrAndPort returns IP address and port in the format IPAddr:Port
func (c ConnInfo) IPAddrAndPort() string {
	return c.IPAddr + ":" + c.PortToString()
}

//PortToString return the port number as a string
func (c ConnInfo) PortToString() string {
	return strconv.Itoa(int(c.Port))
}

//Config contains configurations for this server
var Config rainsdConfig

//load config and stores it into global variable config
func loadConfig() {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal("Could not open config file...", "path", configPath, "error", err)
	}
	json.Unmarshal(file, &Config)
}
