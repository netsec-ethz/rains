package rainspub

import (
	"net"
	"rains/rainsd"
	"rains/rainslib"
	"time"
)

const (
	configPath = "config/rainspub.conf"
)

//Config contains configurations for publishing assertions
var config = defaultConfig
var parser zoneFileParser
var msgParser rainslib.RainsMsgParser

//rainpubConfig lists configurations for publishing zone information
type rainpubConfig struct {
	assertionValidity     time.Duration
	shardValidity         time.Duration
	zoneValidity          time.Duration
	maxAssertionsPerShard uint
	serverAddresses       []rainsd.ConnInfo
	zoneFilePath          string
}

//DefaultConfig is a rainpubConfig object containing default values
var defaultConfig = rainpubConfig{assertionValidity: 30 * 24 * time.Hour, shardValidity: 24 * time.Hour, zoneValidity: 24 * time.Hour, maxAssertionsPerShard: 5,
	serverAddresses: []rainsd.ConnInfo{rainsd.ConnInfo{Type: rainsd.TCP, IPAddr: net.ParseIP("127.0.0.1"), Port: 5022}}}

type zoneFileParser interface {
	//parseZoneFile takes as input a zoneFile and returns all contained assertions. A zoneFile has the following format:
	//:Z: <zone> <context> [(:S:<Shard Content>|:A:<Assertion Content>)*]
	//Shard Content: [(:A:<Assertion Content>)*]
	//Assertion Content: <subject-name>[(:objectType:<object data>)*]
	parseZoneFile(zoneFile []byte) ([]*rainslib.AssertionSection, error)
}

type zoneFileParserImpl struct {
}

func (p zoneFileParserImpl) parseZoneFile(zoneFile []byte) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	return assertions, nil
}
