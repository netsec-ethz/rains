package rainspub

import (
	"net"
	"rains/rainslib"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

const (
	configPath = "config/rainspub.conf"
)

//Config contains configurations for publishing assertions
var config rainpubConfig
var zonePrivateKey ed25519.PrivateKey
var rootPrivateKey ed25519.PrivateKey
var parser rainslib.ZoneFileParser
var msgParser rainslib.RainsMsgParser

//rainpubConfig lists configurations for publishing zone information
type rainpubConfig struct {
	AssertionValidity      time.Duration //in hours
	DelegationValidity     time.Duration //in hours
	ShardValidity          time.Duration //in hours
	ZoneValidity           time.Duration //in hours
	MaxAssertionsPerShard  uint
	ServerAddresses        []rainslib.ConnInfo
	ZoneFilePath           string
	ZoneFileDelegationPath string
	ZonePrivateKeyPath     string
	ZonePublicKeyPath      string
	RootPrivateKeyPath     string
}

func loadDefaultSeverAddrIntoConfig() {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5022")
	if err != nil {
		log.Warn("Was not able to resolve default tcp addr of server")
	}
	config.ServerAddresses = []rainslib.ConnInfo{rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: addr}}
	config.AssertionValidity *= time.Hour
	config.ShardValidity *= time.Hour
	config.ZoneValidity *= time.Hour
	config.DelegationValidity *= time.Hour
}
