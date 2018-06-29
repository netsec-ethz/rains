package zonepub

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
)

func TestLoadConfig(t *testing.T) {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:5022")
	tcpAddr2, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:5023")
	expectedConfig := rainpubConfig{
		AssertionValidUntil:   86400 * time.Hour,
		DelegationValidUntil:  86439 * time.Hour,
		ShardValidUntil:       86400 * time.Hour,
		ZoneValidUntil:        86400 * time.Hour,
		AssertionValidSince:   0,
		DelegationValidSince:  -1 * time.Hour,
		ShardValidSince:       0,
		ZoneValidSince:        0,
		MaxAssertionsPerShard: 5,
		ServerAddresses: []rainslib.ConnInfo{
			rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr},
			rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr2},
		},
		ZoneFilePath:       "zoneFiles/chZoneFile.txt",
		ZonePrivateKeyPath: "test/zonePrivate.key",
	}
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/rainspub.conf", ""},
		{"notExist/rainspub.conf", "open notExist/rainspub.conf: no such file or directory"},
		{"test/malformed.conf", "unexpected end of JSON input"},
	}
	for i, test := range tests {
		err := loadConfig(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: loadconfig() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && !reflect.DeepEqual(config, expectedConfig) {
			t.Errorf("%d: Loaded content is not as expected. expected=%v, actual=%v", i, expectedConfig, config)
		}
	}
}
