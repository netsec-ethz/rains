package rainspub

import (
	"net"
	"rains/rainsd"
	"rains/rainslib"
	"time"

	"golang.org/x/crypto/ed25519"
)

const (
	configPath = "config/rainspub.conf"
)

//Config contains configurations for publishing assertions
var config = defaultConfig
var privateKey ed25519.PrivateKey
var publicKey ed25519.PublicKey
var parser rainslib.ZoneFileParser
var msgParser rainslib.RainsMsgParser

//rainpubConfig lists configurations for publishing zone information
type rainpubConfig struct {
	assertionValidity     time.Duration
	delegationValidity    time.Duration
	shardValidity         time.Duration
	zoneValidity          time.Duration
	maxAssertionsPerShard uint
	serverAddresses       []rainsd.ConnInfo
	zoneFilePath          string
}

//DefaultConfig is a rainpubConfig object containing default values
var defaultConfig = rainpubConfig{assertionValidity: 15 * 24 * time.Hour, shardValidity: 24 * time.Hour, zoneValidity: 24 * time.Hour, maxAssertionsPerShard: 5,
	serverAddresses: []rainsd.ConnInfo{rainsd.ConnInfo{Type: rainsd.TCP, IPAddr: net.ParseIP("127.0.0.1"), Port: 5022}}, delegationValidity: 30 * 24 * time.Hour}
