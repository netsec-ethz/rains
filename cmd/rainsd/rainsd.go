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
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/spf13/cobra"
)

var config = rainsd.DefaultConfig()
var id string
var rootZonePublicKeyPath string
var assertionCheckPointInterval time.Duration
var negAssertionCheckPointInterval time.Duration
var zoneKeyCheckPointInterval time.Duration
var checkPointPath string
var preLoadCaches bool

//switchboard
var serverAddress addressFlag
var rootServerAddress addressFlag
var maxConnections int
var keepAlivePeriod time.Duration
var tcpTimeout time.Duration
var tlsCertificateFile string
var tlsPrivateKeyFile string

//inbox
var prioBufferSize int
var normalBufferSize int
var notificationBufferSize int
var prioWorkerCount int
var normalWorkerCount int
var notificationWorkerCount int
var capabilitiesCacheSize int
var capabilities string

//verify
var zoneKeyCacheSize int
var zoneKeyCacheWarnSize int
var maxPublicKeysPerZone int
var pendingKeyCacheSize int
var delegationQueryValidity time.Duration
var reapZoneKeyCacheInterval time.Duration
var reapPendingKeyCacheInterval time.Duration

//engine
var assertionCacheSize int
var negativeAssertionCacheSize int
var pendingQueryCacheSize int
var queryValidity time.Duration
var authorities authoritiesFlag
var maxAssertionValidity time.Duration
var maxShardValidity time.Duration
var maxPshardValidity time.Duration
var maxZoneValidity time.Duration
var reapAssertionCacheInterval time.Duration
var reapNegAssertionCacheInterval time.Duration
var reapPendingQCacheInterval time.Duration
var maxRecurseDepth int

var rootCmd = &cobra.Command{
	Use:   "rainsd [PATH]",
	Short: "rainsd is an implementation of a RAINS server",
	Long: `	This program implements a RAINS server which serves requests over the RAINS protocol.
	The server can be configured to support the first two modes of operation, authority
	service and query service. The third one is not yet implemented.

	* authority service -- the server acts on behalf of an authority to ensure
	 properly signed assertions are available to the system,
	* query service -- the server acts on behalf of clients to respond to queries
	 with relevant assertions to answer these queries,
	* intermediary service -- the server provides storage and lookup services to
	 authority services and query services.

	If no path to a config file is provided, the default config is used.

	A capability represents a set of features the server supports, and is used for
	advertising functionality to other servers. Currently only the following
	capabilities are supported:

	* 'urn:x-rains:tlssrv'`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 {
			var err error
			if config, err = rainsd.LoadConfig(args[0]); err != nil {
				log.Fatalf("Error: was not able to load config file: %v", err)
			}
		}
	},
}

func init() {
	rootCmd.Flags().Var(&serverAddress, "serverAddress", "The network address of this server.")
	rootCmd.Flags().Var(&authorities, "authorities", "A list of contexts and zones for which this server "+
		"is authoritative. The format is elem(,elem)* where elem := zoneName,contextName")
	rootCmd.Flags().Var(&rootServerAddress, "rootServerAddress", "The root name server address")
	rootCmd.Flags().StringVar(&id, "id", "", "Server id")
	rootCmd.Flags().StringVar(&rootZonePublicKeyPath, "rootZonePublicKeyPath", "data/keys/rootDelegationAssertion.gob", "Path to the "+
		"file storing the RAINS' root zone public key.")
	rootCmd.Flags().DurationVar(&assertionCheckPointInterval, "assertionCheckPointInterval", 30*time.Minute, "The time duration in "+
		"seconds after which a checkpoint of the assertion cache is performed.")
	rootCmd.Flags().DurationVar(&negAssertionCheckPointInterval, "negAssertionCheckPointInterval", time.Hour, "The time duration in seconds "+
		"after which a checkpoint of the negative assertion cache is performed.")
	rootCmd.Flags().DurationVar(&zoneKeyCheckPointInterval, "zoneKeyCheckPointInterval", 30*time.Minute, "The time duration in "+
		"seconds after which a checkpoint of the zone key cache is performed.")
	rootCmd.Flags().StringVar(&checkPointPath, "checkPointPath", "data/checkpoint/resolver/", "Path where the server's "+
		"checkpoint information is stored.")
	rootCmd.Flags().BoolVar(&preLoadCaches, "preLoadCaches", false, "If true, the assertion, negative assertion, "+
		"and zone key cache are pre-loaded from the checkpoint files in CheckPointPath at start up.")

	//switchboard
	rootCmd.Flags().IntVar(&maxConnections, "maxConnections", 10000, "The maximum number of allowed active connections.")
	rootCmd.Flags().DurationVar(&keepAlivePeriod, "keepAlivePeriod", time.Minute, "How long to keep idle connections open.")
	rootCmd.Flags().DurationVar(&tcpTimeout, "tcpTimeout", 5*time.Minute, "TCPTimeout is the maximum amount of "+
		"time a dial will wait for a tcp connect to complete.")
	rootCmd.Flags().StringVar(&tlsCertificateFile, "tlsCertificateFile", "data/cert/server.crt", "The path to the server's tls "+
		"certificate file proving the server's identity.")
	rootCmd.Flags().StringVar(&tlsPrivateKeyFile, "tlsPrivateKeyFile", "data/cert/server.key", "The path to the server's tls "+
		"private key file proving the server's identity.")

	//inbox
	rootCmd.Flags().IntVar(&prioBufferSize, "prioBufferSize", 50, "The maximum number of messages in the priority buffer.")
	rootCmd.Flags().IntVar(&normalBufferSize, "normalBufferSize", 100, "The maximum number of messages in the normal buffer.")
	rootCmd.Flags().IntVar(&notificationBufferSize, "notificationBufferSize", 10, "The maximum number of messages in the notification buffer.")
	rootCmd.Flags().IntVar(&prioWorkerCount, "prioWorkerCount", 2, "Number of workers on the priority queue.")
	rootCmd.Flags().IntVar(&normalWorkerCount, "normalWorkerCount", 10, "Number of workers on the normal queue.")
	rootCmd.Flags().IntVar(&notificationWorkerCount, "notificationWorkerCount", 1, "Number of workers on the notification queue.")
	rootCmd.Flags().IntVar(&capabilitiesCacheSize, "capabilitiesCacheSize", 10, "Maximum number of elements in the capabilities cache.")
	rootCmd.Flags().StringVar(&capabilities, "capabilities", "urn:x-rains:tlssrv", "A list of capabilities this server supports.")

	//verify
	rootCmd.Flags().IntVar(&zoneKeyCacheSize, "zoneKeyCacheSize", 1000, "The maximum number of entries in the zone key cache.")
	rootCmd.Flags().IntVar(&zoneKeyCacheWarnSize, "zoneKeyCacheWarnSize", 750, "When the number of elements in the zone key "+
		"cache exceeds this value, a warning is logged.")
	rootCmd.Flags().IntVar(&maxPublicKeysPerZone, "maxPublicKeysPerZone", 5, "The maximum number of public keys for each zone.")
	rootCmd.Flags().IntVar(&pendingKeyCacheSize, "pendingKeyCacheSize", 100, "The maximum number of entries in the pending key cache.")
	rootCmd.Flags().DurationVar(&delegationQueryValidity, "delegationQueryValidity", time.Second, "The amount of seconds in the "+
		"future when delegation queries are set to expire.")
	rootCmd.Flags().DurationVar(&reapZoneKeyCacheInterval, "reapZoneKeyCacheInterval", 15*time.Minute, "The time interval to wait "+
		"between removing expired entries from the zone key cache.")
	rootCmd.Flags().DurationVar(&reapPendingKeyCacheInterval, "reapPendingKeyCacheInterval", 15*time.Minute, "The time interval to wait "+
		"between removing expired entries from the pending key cache.")

	//engine
	rootCmd.Flags().IntVar(&assertionCacheSize, "assertionCacheSize", 10000, "The maximum number of entries in the "+
		"assertion cache.")
	rootCmd.Flags().IntVar(&negativeAssertionCacheSize, "negativeAssertionCacheSize", 1000, "The maximum number of entries in the "+
		"negative assertion cache.")
	rootCmd.Flags().IntVar(&pendingQueryCacheSize, "pendingQueryCacheSize", 1000, " The maximum number of entries in the "+
		"pending query cache.")
	rootCmd.Flags().DurationVar(&queryValidity, "queryValidity", time.Second, "The amount of seconds in the "+
		"future when a query is set to expire.")
	rootCmd.Flags().DurationVar(&maxAssertionValidity, "maxAssertionValidity", 3*time.Hour, "contains the maximum number "+
		"of seconds an assertion can be in the cache before the cached entry expires. It is not "+
		"guaranteed that expired entries are directly removed.")
	rootCmd.Flags().DurationVar(&maxShardValidity, "maxShardValidity", 3*time.Hour, "contains the maximum number "+
		"of seconds an shard can be in the cache before the cached entry expires. It is not guaranteed"+
		" that expired entries are directly removed.")
	rootCmd.Flags().DurationVar(&maxPshardValidity, "maxPshardValidity", 3*time.Hour, "contains the maximum number of "+
		"seconds an pshard can be in the cache before the cached entry expires. It is not guaranteed "+
		"that expired entries are directly removed.")
	rootCmd.Flags().DurationVar(&maxZoneValidity, "maxZoneValidity", 3*time.Hour, "contains the maximum number of "+
		"seconds an zone can be in the cache before the cached entry expires. It is not guaranteed "+
		"that expired entries are directly removed.")
	rootCmd.Flags().DurationVar(&reapAssertionCacheInterval, "reapAssertionCacheInterval", 15*time.Minute, "The time interval to "+
		"wait between removing expired entries from the assertion cache.")
	rootCmd.Flags().DurationVar(&reapNegAssertionCacheInterval, "reapNegAssertionCacheInterval", 15*time.Minute, " The time interval to "+
		"wait between removing expired entries from the negative assertion cache.")
	rootCmd.Flags().DurationVar(&reapPendingQCacheInterval, "reapPendingQCacheInterval", 15*time.Minute, "The time interval to "+
		"wait between removing expired entries from the pending query cache.")
	rootCmd.Flags().IntVar(&maxRecurseDepth, "maxrecurse", 50, "Recursive resolver maximum depth (max. depth of recursive stack)")
}

func main() {
	h := log15.CallerFileHandler(log15.StdoutHandler)
	log15.Root().SetHandler(log15.LvlFilterHandler(log15.LvlInfo, h))
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
	if !rootCmd.Flag("help").Changed {
		updateConfig(&config)
		server, err := rainsd.New(config, id)
		if err != nil {
			log.Fatalf("Error: Was not able to initialize server: %v", err)
			return
		} else {
			log.Println("Starting server")
		}
		rootNameServers := []net.Addr{rootServerAddress.value.Addr}
		// maxRecurseCount = 50 means the recursion will abort if called to itself more than 50 times
		resolver, err := libresolve.New(rootNameServers, nil, server.Config().RootZonePublicKeyPath,
			libresolve.Recursive, server.Addr(), maxConnections, server.Config().MaxCacheValidity,
			maxRecurseDepth)
		if err != nil {
			log.Fatalf("Error: Unable to initialize recursive resolver: %v", err.Error())
			return
		}
		server.SetResolver(resolver)
		log.Println("Server successfully initialized")
		go server.Start(false, id)
		handleUserInput()
		server.Shutdown()
	}
}

//updateConfig overrides config with the provided cmd line flags
func updateConfig(config *rainsd.Config) {
	if rootCmd.Flag("rootZonePublicKeyPath").Changed {
		config.RootZonePublicKeyPath = rootZonePublicKeyPath
	}
	if rootCmd.Flag("assertionCheckPointInterval").Changed {
		config.AssertionCheckPointInterval = assertionCheckPointInterval
	}
	if rootCmd.Flag("negAssertionCheckPointInterval").Changed {
		config.NegAssertionCheckPointInterval = negAssertionCheckPointInterval
	}
	if rootCmd.Flag("zoneKeyCheckPointInterval").Changed {
		config.ZoneKeyCheckPointInterval = zoneKeyCheckPointInterval
	}
	if rootCmd.Flag("checkPointPath").Changed {
		config.CheckPointPath = checkPointPath
	}
	if rootCmd.Flag("preLoadCaches").Changed {
		config.PreLoadCaches = preLoadCaches
	}
	if rootCmd.Flag("serverAddress").Changed {
		config.ServerAddress = serverAddress.value
	}
	if rootCmd.Flag("maxConnections").Changed {
		config.MaxConnections = maxConnections
	}
	if rootCmd.Flag("keepAlivePeriod").Changed {
		config.KeepAlivePeriod = keepAlivePeriod
	}
	if rootCmd.Flag("tcpTimeout").Changed {
		config.TCPTimeout = tcpTimeout
	}
	if rootCmd.Flag("tlsCertificateFile").Changed {
		config.TLSCertificateFile = tlsCertificateFile
	}
	if rootCmd.Flag("tlsPrivateKeyFile").Changed {
		config.TLSPrivateKeyFile = tlsPrivateKeyFile
	}
	if rootCmd.Flag("prioBufferSize").Changed {
		config.PrioBufferSize = prioBufferSize
	}
	if rootCmd.Flag("normalBufferSize").Changed {
		config.NormalBufferSize = normalBufferSize
	}
	if rootCmd.Flag("notificationBufferSize").Changed {
		config.NotificationBufferSize = notificationBufferSize
	}
	if rootCmd.Flag("prioWorkerCount").Changed {
		config.PrioWorkerCount = prioWorkerCount
	}
	if rootCmd.Flag("normalWorkerCount").Changed {
		config.NormalWorkerCount = normalWorkerCount
	}
	if rootCmd.Flag("notificationWorkerCount").Changed {
		config.NotificationWorkerCount = notificationWorkerCount
	}
	if rootCmd.Flag("capabilitiesCacheSize").Changed {
		config.CapabilitiesCacheSize = capabilitiesCacheSize
	}
	if rootCmd.Flag("capabilities").Changed {
		config.Capabilities = []message.Capability{message.Capability(capabilities)}
	}
	if rootCmd.Flag("zoneKeyCacheSize").Changed {
		config.ZoneKeyCacheSize = zoneKeyCacheSize
	}
	if rootCmd.Flag("zoneKeyCacheWarnSize").Changed {
		config.ZoneKeyCacheWarnSize = zoneKeyCacheWarnSize
	}
	if rootCmd.Flag("maxPublicKeysPerZone").Changed {
		config.MaxPublicKeysPerZone = maxPublicKeysPerZone
	}
	if rootCmd.Flag("pendingKeyCacheSize").Changed {
		config.PendingKeyCacheSize = pendingKeyCacheSize
	}
	if rootCmd.Flag("delegationQueryValidity").Changed {
		config.DelegationQueryValidity = delegationQueryValidity
	}
	if rootCmd.Flag("reapZoneKeyCacheInterval").Changed {
		config.ReapZoneKeyCacheInterval = reapZoneKeyCacheInterval
	}
	if rootCmd.Flag("reapPendingKeyCacheInterval").Changed {
		config.ReapPendingKeyCacheInterval = reapPendingKeyCacheInterval
	}
	if rootCmd.Flag("assertionCacheSize").Changed {
		config.AssertionCacheSize = assertionCacheSize
	}
	if rootCmd.Flag("negativeAssertionCacheSize").Changed {
		config.NegativeAssertionCacheSize = negativeAssertionCacheSize
	}
	if rootCmd.Flag("pendingQueryCacheSize").Changed {
		config.PendingQueryCacheSize = pendingQueryCacheSize
	}
	if rootCmd.Flag("authorities").Changed {
		config.Authorities = authorities.value
	}
	if rootCmd.Flag("maxAssertionValidity").Changed {
		config.MaxCacheValidity.AssertionValidity = maxAssertionValidity
	}
	if rootCmd.Flag("maxShardValidity").Changed {
		config.MaxCacheValidity.ShardValidity = maxShardValidity
	}
	if rootCmd.Flag("maxPshardValidity").Changed {
		config.MaxCacheValidity.PshardValidity = maxPshardValidity
	}
	if rootCmd.Flag("maxZoneValidity").Changed {
		config.MaxCacheValidity.ZoneValidity = maxZoneValidity
	}
	if rootCmd.Flag("reapAssertionCacheInterval").Changed {
		config.ReapAssertionCacheInterval = reapAssertionCacheInterval
	}
	if rootCmd.Flag("reapNegAssertionCacheInterval").Changed {
		config.ReapNegAssertionCacheInterval = reapNegAssertionCacheInterval
	}
	if rootCmd.Flag("reapPendingQCacheInterval").Changed {
		config.ReapPendingQCacheInterval = reapPendingQCacheInterval
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
	if i.set {
		return i.value.Addr.String()
	}
	return "127.0.0.1:55553" //default
}

func (i *addressFlag) Set(value string) (err error) {
	i.set = true
	i.value = connection.Info{}
	i.value.Addr, err = net.ResolveTCPAddr("", value)
	if err != nil { // Not an IP address
		i.value.Addr, err = snet.ParseUDPAddr(value)
		if err == nil {
			i.value.Type = connection.SCION
		}
	} else {
		i.value.Type = connection.TCP
	}
	return err
}

func (i *addressFlag) Type() string {
	return "net.Addr"
}

type authoritiesFlag struct {
	set   bool
	value []rainsd.ZoneContext
}

func (i *authoritiesFlag) String() string {
	if i.set {
		return fmt.Sprintf("%v", i.value)
	}
	return "[]" //default
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
	return "[]zoneContext"
}
