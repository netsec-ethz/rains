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
var config = defaultConfig
var zonePrivateKey ed25519.PrivateKey
var parser rainslib.ZoneFileParser
var msgParser rainslib.RainsMsgParser

//rainpubConfig lists configurations for publishing zone information
type rainpubConfig struct {
	AssertionValidity      time.Duration
	DelegationValidity     time.Duration
	ShardValidity          time.Duration
	ZoneValidity           time.Duration
	MaxAssertionsPerShard  uint
	ServerAddresses        []rainslib.ConnInfo
	ZoneFilePath           string
	ZoneFileDelegationPath string
	ZonePrivateKeyPath     string
	ZonePublicKeyPath      string
}

//DefaultConfig is a rainpubConfig object containing default values
var defaultConfig = rainpubConfig{AssertionValidity: 15 * 24 * time.Hour, ShardValidity: 24 * time.Hour, ZoneValidity: 24 * time.Hour, MaxAssertionsPerShard: 5,
	DelegationValidity: 30 * 24 * time.Hour, ZoneFilePath: "zoneFiles/chZoneFile.txt", ZonePrivateKeyPath: "keys/zonePrivate.key",
	ZonePublicKeyPath: "keys/zonePublic.key", ZoneFileDelegationPath: "zoneFiles/chZoneDelegation.txt"}

func loadDefaultSeverAddrIntoConfig() {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5022")
	if err != nil {
		log.Warn("Was not able to resolve default tcp addr of server")
	}
	config.ServerAddresses = []rainslib.ConnInfo{rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: *addr}}
}
