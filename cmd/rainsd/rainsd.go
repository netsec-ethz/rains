package main

import (
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/tools/keycreator"
	flag "github.com/spf13/pflag"
)

var configPath string
var rootZonePublicKeyPath = flag.String("", "data/keys/rootDelegationAssertion.gob", "Path to the "+
	"file storing the RAINS' root zone public key.")
var assertionCheckPointInterval = flag.Duration("", 30*time.Minute, "The time duration in "+
	"seconds after which a checkpoint of the assertion cache is performed.")
var negAssertionCheckPointInterval = flag.Duration("", time.Hour, "The time duration in seconds "+
	"after which a checkpoint of the negative assertion cache is performed.")
var zoneKeyCheckPointInterval = flag.Duration("", 30*time.Minute, "The time duration in "+
	"seconds after which a checkpoint of the zone key cache is performed.")
var checkPointPath = flag.String("", "data/checkpoint/resolver/", "Path where the server's "+
	"checkpoint information is stored.")
var preLoadCaches = flag.Bool("doSharding", false, "If true, the assertion, negative assertion, "+
	"and zone key cache are pre-loaded from the checkpoint files in CheckPointPath at start up.")

//switchboard
var serverAddress addressesFlag
var maxConnections = flag.Int("maxConnections", 10000, "The maximum number of allowed active connections.")
var keepAlivePeriod = flag.Duration("keepAlivePeriod", time.Minute, "How long to keep idle connections open.")
var tCPTimeout = flag.Duration("tCPTimeout", 5*time.Minute, "TCPTimeout is the maximum amount of "+
	"time a dial will wait for a tcp connect to complete.")
var tLSCertificateFile = flag.String("tLSCertificateFile", "data/cert/server.crt", "The path to the server's tls "+
	"certificate file proving the server's identity.")
var tLSPrivateKeyFile = flag.String("tLSPrivateKeyFile", "data/cert/server.key", "The path to the server's tls "+
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
var authorities addressesFlag //TODO create correct flag
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
	addr := "The network address of this server."
	auths := "A list of contexts and zones for which this server is authoritative."
}

func main() {

	keycreator.DelegationAssertion(".", ".", "keys/selfSignedRootDelegationAssertion.gob", "keys/rootPrivateKey.txt")
	server, err := rainsd.New("config/server.conf", "0")
	if err != nil {
		log.Error(err.Error())
		return
	}
	log.Info("Server successfully initialized")
	server.SetResolver(libresolve.New(nil, nil, libresolve.Recursive, server.Addr(), 10000))
	go server.Start(false)
	time.Sleep(time.Hour)
	server.Shutdown()
	log.Info("Server shut down")
}

type addressesFlag struct {
	set   bool
	value connection.Info
}

func (i *addressesFlag) String() string {
	return fmt.Sprint("127.0.0.1:55553")
}

func (i *addressesFlag) Set(value string) error {
	i.set = true
	if tcpAddr, err := net.ResolveTCPAddr("tcp", value); err == nil {
		i.value = append(i.value, connection.Info{Type: connection.TCP, Addr: tcpAddr})
	} else {
		return err
	}
	return nil
}

func (i *addressesFlag) Type() string {
	return fmt.Sprintf("%T", *i)
}
