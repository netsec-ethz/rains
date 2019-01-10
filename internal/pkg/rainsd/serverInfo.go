package rainsd

import (
	"fmt"
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
	PublisherAddress   connection.Info
	MaxConnections     int
	KeepAlivePeriod    time.Duration //in seconds
	TCPTimeout         time.Duration //in seconds
	TLSCertificateFile string
	TLSPrivateKeyFile  string

	//inbox
	MaxMsgByteLength        uint
	PrioBufferSize          uint
	NormalBufferSize        uint
	NotificationBufferSize  uint
	PrioWorkerCount         uint
	NormalWorkerCount       uint
	NotificationWorkerCount uint
	CapabilitiesCacheSize   int
	PeerToCapCacheSize      uint
	ActiveTokenCacheSize    uint
	Capabilities            []message.Capability

	//verify
	ZoneKeyCacheSize           int
	ZoneKeyCacheWarnSize       int
	MaxPublicKeysPerZone       int
	PendingKeyCacheSize        int
	InfrastructureKeyCacheSize uint
	ExternalKeyCacheSize       uint
	DelegationQueryValidity    time.Duration //in seconds
	ReapVerifyTimeout          time.Duration //in seconds

	//engine
	AssertionCacheSize         int
	NegativeAssertionCacheSize int
	PendingQueryCacheSize      int
	RedirectionCacheSize       int
	RedirectionCacheWarnSize   int
	QueryValidity              time.Duration //in seconds
	AddressQueryValidity       time.Duration //in seconds
	ContextAuthority           []string
	ZoneAuthority              []string
	MaxCacheValidity           util.MaxCacheValidity //in hours
	ReapEngineTimeout          time.Duration         //in seconds
}

type missingKeyMetaData struct {
	Zone     string
	Context  string
	KeyPhase int
}

//zoneContext stores a context and a zone
type zoneContext struct {
	Zone    string
	Context string
}

//zoneAndName contains zone and name which together constitute a fully qualified name
type zoneAndName struct {
	zone string
	name string
}

func (e *zoneAndName) fullyQualifiedName() string {
	return fmt.Sprintf("%s.%s", e.name, e.zone)
}
