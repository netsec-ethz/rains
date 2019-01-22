package rainsd

import (
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

// globalTracer is used to report traces to the tracing server.
var globalTracer *Tracer

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	//general
	RootZonePublicKeyPath string
	//TODO add these two options to man page
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
	PrioBufferSize          uint
	NormalBufferSize        uint
	NotificationBufferSize  uint
	PrioWorkerCount         uint
	NormalWorkerCount       uint
	NotificationWorkerCount uint
	CapabilitiesCacheSize   int
	Capabilities            []message.Capability

	//verify
	ZoneKeyCacheSize           int
	ZoneKeyCacheWarnSize       int
	MaxPublicKeysPerZone       int
	PendingKeyCacheSize        int
	DelegationQueryValidity    time.Duration //in seconds
	ReapZoneKeyCacheTimeout    time.Duration //in seconds
	ReapPendingKeyCacheTimeout time.Duration //in seconds

	//engine
	AssertionCacheSize           int
	NegativeAssertionCacheSize   int
	PendingQueryCacheSize        int
	QueryValidity                time.Duration //in seconds
	Authorities                  []ZoneContext
	MaxCacheValidity             util.MaxCacheValidity //in hours
	ReapAssertionCacheTimeout    time.Duration         //in seconds
	ReapNegAssertionCacheTimeout time.Duration         //in seconds
	ReapPendingQCacheTimeout     time.Duration         //in seconds
}
