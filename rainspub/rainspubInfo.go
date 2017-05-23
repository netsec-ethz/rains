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
var parser rainslib.ZoneFileParser
var msgParser rainslib.RainsMsgParser

//rainpubConfig lists configurations for publishing zone information
type rainpubConfig struct {
	AssertionValidity     time.Duration
	DelegationValidity    time.Duration
	ShardValidity         time.Duration
	ZoneValidity          time.Duration
	MaxAssertionsPerShard uint
	ServerAddresses       []rainsd.ConnInfo
	ZoneFilePath          string
	ZonePrivateKeyPath    string
	ZonePublicKeyPath     string
}

//DefaultConfig is a rainpubConfig object containing default values
var defaultConfig = rainpubConfig{AssertionValidity: 15 * 24 * time.Hour, ShardValidity: 24 * time.Hour, ZoneValidity: 24 * time.Hour, MaxAssertionsPerShard: 5,
	ServerAddresses: []rainsd.ConnInfo{rainsd.ConnInfo{Type: rainsd.TCP, IPAddr: net.ParseIP("127.0.0.1"), Port: 5022}}, DelegationValidity: 30 * 24 * time.Hour,
	ZoneFilePath: "zoneFiles/chZoneFile.txt", ZonePrivateKeyPath: "keys/zonePrivate.key", ZonePublicKeyPath: "keys/zonePublic.key"}
