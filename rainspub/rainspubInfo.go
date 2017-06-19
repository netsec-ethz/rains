package rainspub

import (
	"rains/rainslib"
	"time"

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
