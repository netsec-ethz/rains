package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	flag "github.com/spf13/pflag"
)

var configPath string
var rootZonePublicKeyPath = flag.String("rootZonePublicKeyPath", "data/keys/rootDelegationAssertion.gob", "Path to the "+
	"file storing the RAINS' root zone public key.")
var assertionCheckPointInterval = flag.Duration("assertionCheckPointInterval", 30*time.Minute, "The time duration in "+
	"seconds after which a checkpoint of the assertion cache is performed.")
var negAssertionCheckPointInterval = flag.Duration("negAssertionCheckPointInterval", time.Hour, "The time duration in seconds "+
	"after which a checkpoint of the negative assertion cache is performed.")
var zoneKeyCheckPointInterval = flag.Duration("zoneKeyCheckPointInterval", 30*time.Minute, "The time duration in "+
	"seconds after which a checkpoint of the zone key cache is performed.")
var checkPointPath = flag.String("checkPointPath", "data/checkpoint/resolver/", "Path where the server's "+
	"checkpoint information is stored.")
var preLoadCaches = flag.Bool("preLoadCaches", false, "If true, the assertion, negative assertion, "+
	"and zone key cache are pre-loaded from the checkpoint files in CheckPointPath at start up.")

//switchboard
var serverAddress addressFlag
var maxConnections = flag.Int("maxConnections", 10000, "The maximum number of allowed active connections.")
var keepAlivePeriod = flag.Duration("keepAlivePeriod", time.Minute, "How long to keep idle connections open.")
var tcpTimeout = flag.Duration("tcpTimeout", 5*time.Minute, "TCPTimeout is the maximum amount of "+
	"time a dial will wait for a tcp connect to complete.")
var tlsCertificateFile = flag.String("tlsCertificateFile", "data/cert/server.crt", "The path to the server's tls "+
	"certificate file proving the server's identity.")
var tlsPrivateKeyFile = flag.String("tlsPrivateKeyFile", "data/cert/server.key", "The path to the server's tls "+
	"private key file proving the server's identity.")

// SCION specific settings
var dispatcherSock = flag.String("dispatcherSock", "", "TODO write description")
var sciondSock = flag.String("sciondSock", "", "TODO write description")

//inbox
var prioBufferSize = flag.Int("prioBufferSize", 50, "The maximum number of messages in the priority buffer.")
var normalBufferSize = flag.Int("normalBufferSize", 100, "The maximum number of messages in the normal buffer.")
var notificationBufferSize = flag.Int("notificationBufferSize", 10, "The maximum number of messages in the notification buffer.")
var prioWorkerCount = flag.Int("prioWorkerCount", 2, "Number of workers on the priority queue.")
var normalWorkerCount = flag.Int("normalWorkerCount", 10, "Number of workers on the normal queue.")
var notificationWorkerCount = flag.Int("notificationWorkerCount", 1, "Number of workers on the notification queue.")
var capabilitiesCacheSize = flag.Int("capabilitiesCacheSize", 10, "Maximum number of elements in the capabilities cache.")
var capabilities = flag.String("capabilities", "urn:x-rains:tlssrv", "A list of capabilities this server supports.")

//verify
var zoneKeyCacheSize = flag.Int("zoneKeyCacheSize", 1000, "The maximum number of entries in the zone key cache.")
var zoneKeyCacheWarnSize = flag.Int("zoneKeyCacheWarnSize", 750, "When the number of elements in the zone key "+
	"cache exceeds this value, a warning is logged.")
var maxPublicKeysPerZone = flag.Int("maxPublicKeysPerZone", 5, "The maximum number of public keys for each zone.")
var pendingKeyCacheSize = flag.Int("pendingKeyCacheSize", 100, "The maximum number of entries in the pending key cache.")
var delegationQueryValidity = flag.Duration("delegationQueryValidity", time.Second, "The amount of seconds in the "+
	"future when delegation queries are set to expire.")
var reapZoneKeyCacheInterval = flag.Duration("reapZoneKeyCacheInterval", 15*time.Minute, "The time interval to wait "+
	"between removing expired entries from the zone key cache.")
var reapPendingKeyCacheInterval = flag.Duration("reapPendingKeyCacheInterval", 15*time.Minute, "The time interval to wait "+
	"between removing expired entries from the pending key cache.")

//engine
var assertionCacheSize = flag.Int("assertionCacheSize", 10000, "The maximum number of entries in the "+
	"assertion cache.")
var negativeAssertionCacheSize = flag.Int("negativeAssertionCacheSize", 1000, "The maximum number of entries in the "+
	"negative assertion cache.")
var pendingQueryCacheSize = flag.Int("pendingQueryCacheSize", 1000, " The maximum number of entries in the "+
	"pending query cache.")
var queryValidity = flag.Duration("queryValidity", time.Second, "The amount of seconds in the "+
	"future when a query is set to expire.")
var authorities authoritiesFlag
var maxAssertionValidity = flag.Duration("maxAssertionValidity", 3*time.Hour, "contains the maximum number "+
	"of seconds an assertion can be in the cache before the cached entry expires. It is not "+
	"guaranteed that expired entries are directly removed.")
var maxShardValidity = flag.Duration("maxShardValidity", 3*time.Hour, "contains the maximum number "+
	"of seconds an shard can be in the cache before the cached entry expires. It is not guaranteed"+
	" that expired entries are directly removed.")
var maxPshardValidity = flag.Duration("maxPshardValidity", 3*time.Hour, "contains the maximum number of "+
	"seconds an pshard can be in the cache before the cached entry expires. It is not guaranteed "+
	"that expired entries are directly removed.")
var maxZoneValidity = flag.Duration("maxZoneValidity", 3*time.Hour, "contains the maximum number of "+
	"seconds an zone can be in the cache before the cached entry expires. It is not guaranteed "+
	"that expired entries are directly removed.")
var reapAssertionCacheInterval = flag.Duration("reapAssertionCacheInterval", 15*time.Minute, "The time interval to "+
	"wait between removing expired entries from the assertion cache.")
var reapNegAssertionCacheInterval = flag.Duration("reapNegAssertionCacheInterval", 15*time.Minute, " The time interval to "+
	"wait between removing expired entries from the negative assertion cache.")
var reapPendingQCacheInterval = flag.Duration("reapPendingQCacheInterval", 15*time.Minute, "The time interval to "+
	"wait between removing expired entries from the pending query cache.")

func init() {
	flag.Var(&serverAddress, "serverAddress", "The network address of this server.")
	flag.Var(&authorities, "authorities", "A list of contexts and zones for which this server "+
		"is authoritative. The format is elem(,elem)* where elem := zoneName,contextName")
}

func main() {
	h := log15.CallerFileHandler(log15.StdoutHandler)
	log15.Root().SetHandler(log15.LvlFilterHandler(log15.LvlInfo, h))
	flag.Parse()
	config := rainsd.DefaultConfig()
	switch flag.NArg() {
	case 0: //default config
	case 1:
		var err error
		if config, err = rainsd.LoadConfig(flag.Arg(0)); err != nil {
			log.Fatalf("Error: was not able to load config file: %v", err)
		}
	default:
		log.Fatalf("Error: too many arguments specified. At most one is allowed. Got %d", flag.NArg())
	}

	updateConfig(&config)
	server, err := rainsd.New(config, "0")
	if err != nil {
		log.Fatalf("Error: Was not able to initialize server: %v", err)
		return
	}
	server.SetResolver(libresolve.New(nil, nil, libresolve.Recursive, server.Addr(), 10000))
	go server.Start(false)
	handleUserInput()
	server.Shutdown()
	log.Println("Server shut down")
}

//updateConfig overrides config with the provided cmd line flags
func updateConfig(config *rainsd.Config) {
	if flag.Lookup("rootZonePublicKeyPath").Changed {
		config.RootZonePublicKeyPath = *rootZonePublicKeyPath
	}
	if flag.Lookup("assertionCheckPointInterval").Changed {
		config.AssertionCheckPointInterval = *assertionCheckPointInterval
	}
	if flag.Lookup("negAssertionCheckPointInterval").Changed {
		config.NegAssertionCheckPointInterval = *negAssertionCheckPointInterval
	}
	if flag.Lookup("zoneKeyCheckPointInterval").Changed {
		config.ZoneKeyCheckPointInterval = *zoneKeyCheckPointInterval
	}
	if flag.Lookup("checkPointPath").Changed {
		config.CheckPointPath = *checkPointPath
	}
	if flag.Lookup("preLoadCaches").Changed {
		config.PreLoadCaches = *preLoadCaches
	}
	if flag.Lookup("serverAddress").Changed {
		config.ServerAddress = serverAddress.value
	}
	if flag.Lookup("maxConnections").Changed {
		config.MaxConnections = *maxConnections
	}
	if flag.Lookup("keepAlivePeriod").Changed {
		config.KeepAlivePeriod = *keepAlivePeriod
	}
	if flag.Lookup("tcpTimeout").Changed {
		config.TCPTimeout = *tcpTimeout
	}
	if flag.Lookup("tlsCertificateFile").Changed {
		config.TLSCertificateFile = *tlsCertificateFile
	}
	if flag.Lookup("tlsPrivateKeyFile").Changed {
		config.TLSPrivateKeyFile = *tlsPrivateKeyFile
	}
	if flag.Lookup("dispatcherSock").Changed {
		config.DispatcherSock = *dispatcherSock
	}
	if flag.Lookup("sciondSock").Changed {
		config.SciondSock = *sciondSock
	}
	if flag.Lookup("prioBufferSize").Changed {
		config.PrioBufferSize = *prioBufferSize
	}
	if flag.Lookup("normalBufferSize").Changed {
		config.NormalBufferSize = *normalBufferSize
	}
	if flag.Lookup("notificationBufferSize").Changed {
		config.NotificationBufferSize = *notificationBufferSize
	}
	if flag.Lookup("prioWorkerCount").Changed {
		config.PrioWorkerCount = *prioWorkerCount
	}
	if flag.Lookup("normalWorkerCount").Changed {
		config.NormalWorkerCount = *normalWorkerCount
	}
	if flag.Lookup("notificationWorkerCount").Changed {
		config.NotificationWorkerCount = *notificationWorkerCount
	}
	if flag.Lookup("capabilitiesCacheSize").Changed {
		config.CapabilitiesCacheSize = *capabilitiesCacheSize
	}
	if flag.Lookup("capabilities").Changed {
		config.Capabilities = []message.Capability{message.Capability(*capabilities)}
	}
	if flag.Lookup("zoneKeyCacheSize").Changed {
		config.ZoneKeyCacheSize = *zoneKeyCacheSize
	}
	if flag.Lookup("zoneKeyCacheWarnSize").Changed {
		config.ZoneKeyCacheWarnSize = *zoneKeyCacheWarnSize
	}
	if flag.Lookup("maxPublicKeysPerZone").Changed {
		config.MaxPublicKeysPerZone = *maxPublicKeysPerZone
	}
	if flag.Lookup("pendingKeyCacheSize").Changed {
		config.PendingKeyCacheSize = *pendingKeyCacheSize
	}
	if flag.Lookup("delegationQueryValidity").Changed {
		config.DelegationQueryValidity = *delegationQueryValidity
	}
	if flag.Lookup("reapZoneKeyCacheInterval").Changed {
		config.ReapZoneKeyCacheInterval = *reapZoneKeyCacheInterval
	}
	if flag.Lookup("reapPendingKeyCacheInterval").Changed {
		config.ReapPendingKeyCacheInterval = *reapPendingKeyCacheInterval
	}
	if flag.Lookup("assertionCacheSize").Changed {
		config.AssertionCacheSize = *assertionCacheSize
	}
	if flag.Lookup("negativeAssertionCacheSize").Changed {
		config.NegativeAssertionCacheSize = *negativeAssertionCacheSize
	}
	if flag.Lookup("pendingQueryCacheSize").Changed {
		config.PendingQueryCacheSize = *pendingQueryCacheSize
	}
	if flag.Lookup("authorities").Changed {
		config.Authorities = authorities.value
	}
	if flag.Lookup("maxAssertionValidity").Changed {
		config.MaxCacheValidity.AssertionValidity = *maxAssertionValidity
	}
	if flag.Lookup("maxShardValidity").Changed {
		config.MaxCacheValidity.ShardValidity = *maxShardValidity
	}
	if flag.Lookup("maxPshardValidity").Changed {
		config.MaxCacheValidity.PshardValidity = *maxPshardValidity
	}
	if flag.Lookup("maxZoneValidity").Changed {
		config.MaxCacheValidity.ZoneValidity = *maxZoneValidity
	}
	if flag.Lookup("reapAssertionCacheInterval").Changed {
		config.ReapAssertionCacheInterval = *reapAssertionCacheInterval
	}
	if flag.Lookup("reapNegAssertionCacheInterval").Changed {
		config.ReapNegAssertionCacheInterval = *reapNegAssertionCacheInterval
	}
	if flag.Lookup("reapPendingQCacheInterval").Changed {
		config.ReapPendingQCacheInterval = *reapPendingQCacheInterval
	}
}

func handleUserInput() {
	time.Sleep(500 * time.Millisecond)
	fmt.Println("Enter q or quit to shutdown the server")
	var input string
	for true {
		fmt.Scanln(&input)
		if input == "q" || input == "quit" {
			return
		}
	}
}

type addressFlag struct {
	set   bool
	value connection.Info
}

func (i *addressFlag) String() string {
	return fmt.Sprint("127.0.0.1:55553")
}

func (i *addressFlag) Set(value string) (err error) {
	i.set = true
	i.value = connection.Info{Type: connection.TCP}
	i.value.Addr, err = net.ResolveTCPAddr("", value)
	return
}

func (i *addressFlag) Type() string {
	return fmt.Sprintf("%T", *i)
}

type authoritiesFlag struct {
	set   bool
	value []rainsd.ZoneContext
}

func (i *authoritiesFlag) String() string {
	return fmt.Sprint("[]")
}

func (i *authoritiesFlag) Set(value string) error {
	var values []string
	values = strings.Split(value, ",")
	if len(values)%2 != 0 {
		return errors.New("Error: amount of zone and context values is not the same")
	}
	i.set = true
	for j := 0; j < len(values); j += 2 {
		i.value = append(i.value, rainsd.ZoneContext{Zone: values[j], Context: values[j+1]})
	}
	return nil
}

func (i *authoritiesFlag) Type() string {
	return fmt.Sprintf("%T", *i)
}
