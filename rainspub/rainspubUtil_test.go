package rainspub

import (
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/rainslib"

	"golang.org/x/crypto/ed25519"
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

func TestLoadPrivateKeys(t *testing.T) {
	var expectedPrivateKey ed25519.PrivateKey
	expectedPrivateKey = make([]byte, hex.DecodedLen(len("80e1a328b908c2d6c2f10659355b15618ead2e42acf1dfcf39488fc7006c444e2245137bcb058f799843bb8c6df31927b547e4951142b99ae97c668b076e9d84")))
	hex.Decode(expectedPrivateKey, []byte("80e1a328b908c2d6c2f10659355b15618ead2e42acf1dfcf39488fc7006c444e2245137bcb058f799843bb8c6df31927b547e4951142b99ae97c668b076e9d84"))
	var tests = []struct {
		input  string
		errMsg string
	}{
		{"test/zonePrivate.key", ""},
		{"notExist/zonePrivate.key", "open notExist/zonePrivate.key: no such file or directory"},
		{"test/malformed.conf", "encoding/hex: invalid byte: U+007B '{'"},
		{"test/zonePrivateWrongSize.key", "Private key length is incorrect"},
	}
	for i, test := range tests {
		err := loadPrivateKey(test.input)
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: loadPrivateKey() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil && !reflect.DeepEqual(expectedPrivateKey, zonePrivateKey) {
			t.Errorf("%d: Loaded privateKey is not as expected. expected=%v, actual=%v", i, expectedPrivateKey, zonePrivateKey)
		}
	}
}
