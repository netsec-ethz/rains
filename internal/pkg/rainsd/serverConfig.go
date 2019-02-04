package rainsd

import (
	"net"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

//Config lists possible configurations of a rains server
type Config struct {
	//general
	RootZonePublicKeyPath          string
	AssertionCheckPointInterval    time.Duration //in seconds
	NegAssertionCheckPointInterval time.Duration //in seconds
	ZoneKeyCheckPointInterval      time.Duration //in seconds
	CheckPointPath                 string
	PreLoadCaches                  bool

	//switchboard
	ServerAddress      connection.Info
	MaxConnections     int
	KeepAlivePeriod    time.Duration //in seconds
	TCPTimeout         time.Duration //in seconds
	TLSCertificateFile string
	TLSPrivateKeyFile  string

	// SCION specific settings
	DispatcherSock string
	SciondSock     string

	//inbox
	PrioBufferSize          int
	NormalBufferSize        int
	NotificationBufferSize  int
	PrioWorkerCount         int
	NormalWorkerCount       int
	NotificationWorkerCount int
	CapabilitiesCacheSize   int
	Capabilities            []message.Capability

	//verify
	ZoneKeyCacheSize            int
	ZoneKeyCacheWarnSize        int
	MaxPublicKeysPerZone        int
	PendingKeyCacheSize         int
	DelegationQueryValidity     time.Duration //in seconds
	ReapZoneKeyCacheInterval    time.Duration //in seconds
	ReapPendingKeyCacheInterval time.Duration //in seconds

	//engine
	AssertionCacheSize            int
	NegativeAssertionCacheSize    int
	PendingQueryCacheSize         int
	QueryValidity                 time.Duration //in seconds
	Authorities                   []ZoneContext
	MaxCacheValidity              util.MaxCacheValidity //in hours
	ReapAssertionCacheInterval    time.Duration         //in seconds
	ReapNegAssertionCacheInterval time.Duration         //in seconds
	ReapPendingQCacheInterval     time.Duration         //in seconds
}

//DefaultConfig return the default configuration for the zone publisher.
func DefaultConfig() Config {
	serverAddr, _ := net.ResolveTCPAddr("", "127.0.0.1:55553")
	return Config{
		RootZonePublicKeyPath:          "data/keys/rootDelegationAssertion.gob",
		AssertionCheckPointInterval:    30 * time.Minute,
		NegAssertionCheckPointInterval: time.Hour,
		ZoneKeyCheckPointInterval:      30 * time.Minute,
		CheckPointPath:                 "data/checkpoint/resolver/",
		PreLoadCaches:                  false,

		//switchboard
		ServerAddress: connection.Info{
			Type: connection.TCP,
			Addr: serverAddr,
		},
		MaxConnections:     10000,
		KeepAlivePeriod:    time.Minute,
		TCPTimeout:         5 * time.Minute,
		TLSCertificateFile: "data/cert/server.crt",
		TLSPrivateKeyFile:  "data/cert/server.key",

		// SCION specific settings
		DispatcherSock: "TODO determine default value",
		SciondSock:     "TODO determine default value",

		//inbox
		PrioBufferSize:          50,
		NormalBufferSize:        1000,
		NotificationBufferSize:  10,
		PrioWorkerCount:         2,
		NormalWorkerCount:       10,
		NotificationWorkerCount: 1,
		CapabilitiesCacheSize:   10,
		Capabilities:            []message.Capability{message.Capability("urn:x-rains:tlssrv")},

		//verify
		ZoneKeyCacheSize:            1000,
		ZoneKeyCacheWarnSize:        750,
		MaxPublicKeysPerZone:        5,
		PendingKeyCacheSize:         100,
		DelegationQueryValidity:     time.Second,
		ReapZoneKeyCacheInterval:    15 * time.Minute,
		ReapPendingKeyCacheInterval: 15 * time.Minute,

		//engine
		AssertionCacheSize:         10000,
		NegativeAssertionCacheSize: 1000,
		PendingQueryCacheSize:      1000,
		QueryValidity:              time.Second,
		Authorities:                []ZoneContext{},
		MaxCacheValidity: util.MaxCacheValidity{
			AssertionValidity: 3 * time.Hour,
			ShardValidity:     3 * time.Hour,
			PshardValidity:    3 * time.Hour,
			ZoneValidity:      3 * time.Hour,
		},
		ReapAssertionCacheInterval:    15 * time.Minute,
		ReapNegAssertionCacheInterval: 15 * time.Minute,
		ReapPendingQCacheInterval:     15 * time.Minute,
	}
}
