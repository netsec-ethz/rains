package rainsd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strconv"
	"time"
)

const (
	configPath = "config/server.conf"
)

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	ServerIPAddr    string
	ServerPort      uint16
	MaxConnections  uint
	KeepAlivePeriod time.Duration
	TCPTimeout      time.Duration

	PrioBufferSize   uint
	NormalBufferSize uint
	PrioWorkerSize   uint
	NormalWorkerSize uint

	CertificateFile string
	PrivateKeyFile  string
}

//DefaultConfig is a rainsdConfig object containing default values
var defaultConfig = rainsdConfig{ServerIPAddr: "127.0.0.1", ServerPort: 5022, MaxConnections: 1000, KeepAlivePeriod: time.Minute, TCPTimeout: 5 * time.Minute,
	PrioBufferSize: 1000, NormalBufferSize: 100000, PrioWorkerSize: 2, NormalWorkerSize: 10, CertificateFile: "config/server.crt", PrivateKeyFile: "config/server.key"}

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
	Msg    []byte
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
