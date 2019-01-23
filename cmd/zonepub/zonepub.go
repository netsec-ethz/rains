package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	flag "github.com/spf13/pflag"
)

var configPath string
var zonefilePath = flag.String("zonefilePath", "data/zonefiles/zf.txt", "Path to the zonefile")
var authServers addressesFlag
var privateKeyPath = flag.String("privateKeyPath", "data/keys/key_sec.pem", "Path to a file storing the private keys. "+
	"Each line contains a key phase as integer and a private key encoded in hexadecimal separated by a space.")
var doSharding = flag.Bool("doSharding", true, "If set to true, all assertions in the zonefile "+
	"are grouped into pshards based on keepPshards, nofAssertionsPerPshard, bFAlgo, BFHash, and "+
	"bloomFilterSize parameters.")
var keepShards = flag.Bool("keepShards", false, "this option only has an effect when DoSharding "+
	"is true. If the zonefile already contains shards, they are kept. Otherwise, all existing "+
	"shards are removed before the new ones are created.")

var nofAssertionsPerShard = flag.Int("nofAssertionsPerShard", -1,
	"this option only has an effect when DoSharding is true. Defines the number of assertions per shard")
var maxShardSize = flag.Int("maxShardSize", 1000, "this option only has an effect when DoSharding is "+
	"true. Assertions are added to a shard until its size would become larger than maxShardSize in "+
	"bytes. Then the process is repeated with a new shard.")
var doPsharding = flag.Bool("doPsharding", true, "If set to true, all assertions in the zonefile "+
	"are grouped into pshards based on keepPshards, nofAssertionsPerPshard, bFAlgo, BFHash, and "+
	"bloomFilterSize parameters.")
var keepPshards = flag.Bool("keepPshards", false, "this option only has an effect when "+
	"DoPsharding is true. If the zonefile already contains pshards, they are kept. "+
	"Otherwise, all existing pshards are removed before the new ones are created.")

var nofAssertionsPerPshard = flag.Int("nofAssertionsPerPshard", 50, "this option only has an effect"+
	"when doPsharding is true. Defines the number of assertions with different names per pshard.")
var bfAlgo bfAlgoFlag
var bfHash bfHashFlag
var bloomFilterSize = flag.Int("bloomFilterSize", 200, "Number of bytes in the bloom filter.")
var addSignatureMetaData = flag.Bool("addSignatureMetaData", true, "If set to true, adds "+
	"signature meta data to sections")
var addSigMetaDataToAssertions = flag.Bool("addSigMetaDataToAssertions", true, "this option "+
	"only has an effect when AddSignatureMetaData is true. If set to true, signature meta data is "+
	"added to all assertions contained in a shard or zone.")
var addSigMetaDataToShards = flag.Bool("addSigMetaDataToShards", true, "this option only has "+
	"an effect when AddSignatureMetaData is true. If set to true, signature meta data is added to "+
	"all shards contained the zone.")
var addSigMetaDataToPshards = flag.Bool("addSigMetaDataToPshards", true, "this option only "+
	"has an effect when AddSignatureMetaData is true. If set to true, signature meta data is added "+
	"to all pshards contained the zone.")
var signatureAlgorithm algoFlag
var keyPhase = flag.Int("keyPhase", 0, "this option only has an effect when addSignatureMetaData "+
	"is true. Defines the key phase in which the sections will be signed. Together with KeyPhase this "+
	"uniquely defines which private key will be used. (default 0)")
var sigValidSince = flag.Int64("sigValidSince", 0, "this option only has an effect when "+
	"addSignatureMetaData is true. Defines the starting point of the SigSigningInterval for the Signature "+
	"validSince values. Assertions' validSince values are uniformly spread out over this interval. "+
	"Value must be an int64 representing unix seconds since 1.1.1970. (default current time)")
var sigValidUntil = flag.Int64("sigValidUntil", -1, "this option only has an effect when "+
	"addSignatureMetaData is true. Defines the starting point of the SigSigningInterval for the "+
	"Signature validUntil values. Assertions' validUntil values are uniformly spread out over this "+
	"interval. Value must be an int64 representing unix seconds since 1.1.1970 (default current "+
	"time plus 24 hours)")
var sigSigningInterval = flag.Int64("sigSigningInterval", 0, "this option only has an effect when "+
	"addSignatureMetaData is true. Defines the time interval in seconds over which the assertions' "+
	"signature lifetimes are uniformly spread out. (default 1 minute)")
var doConsistencyCheck = flag.Bool("doConsistencyCheck", true, "Performs all consistency checks "+
	"if set to true. The check involves: sorting shards, sorting zones, checking that no signature "+
	"is expired, and that all string fields contain no protocol keywords.")
var sortShards = flag.Bool("sortShards", false, "If set to true, makes sure that the assertions "+
	"withing the shard are sorted.")
var sortZone = flag.Bool("sortZone", false, "If set to true, makes sure that the assertions "+
	"withing the zone are sorted.")
var sigNotExpired = flag.Bool("sigNotExpired", false, "If set to true, checks that all signatures "+
	"have a validUntil time in the future")
var checkStringFields = flag.Bool("checkStringFields", false, "If set to true, checks that none "+
	"of the assertions' text fields contain	protocol keywords.")
var doSigning = flag.Bool("doSigning", true, "If set to true, all sections with signature meta "+
	"data are signed.")
var maxZoneSize = flag.Int("maxZoneSize", 60000, "this option only has an effect when doSigning is "+
	"true. If the zone's size is larger than maxZoneSize then only the zone's content is signed but "+
	"not the zone itself.")
var outputPath = flag.String("outputPath", "", "If not an empty string, a zonefile with the signed "+
	"sections is generated and stored at the provided path. (default \"\")")
var doPublish = flag.Bool("doPublish", true, "If set to true, sends the signed sections to all "+
	"authoritative rains servers. If the zone is smaller than the maximum allowed size, the zone is "+
	"sent. Otherwise, the zone section's content is sent separately such that the maximum message "+
	"size is not exceeded.")

func init() {
	flag.Var(&authServers, "authServers", "Authoritative server addresses to which the sections "+
		"in the zone file are forwarded.")
	flag.Var(&bfAlgo, "bfAlgo", "Bloom filter's algorithm.")
	flag.Var(&bfHash, "bfHash", "Hash algorithm used to add to or check bloomfilter.")
	flag.Var(&signatureAlgorithm, "signatureAlgorithm", "this option only has an "+
		"effect when addSignatureMetaData is true. Defines which algorithm will be used for signing. "+
		"Together with keyPhase this uniquely defines which private key will be used.")
}

//main initializes rainspub
func main() {
	flag.Parse()
	config := publisher.DefaultConfig()
	switch flag.NArg() {
	case 0: //default config
	case 1:
		var err error
		if config, err = publisher.LoadConfig(flag.Arg(0)); err != nil {
			log.Fatalf("Error: was not able to load config file: %v", err)
		}
	default:
		log.Fatalf("Error: too many arguments specified. At most one is allowed. Got %d", flag.NArg())
	}

	updateConfig(&config)
	server := publisher.New(config)
	server.Publish()
}

//updateConfig overrides config with the provided cmd line flags
func updateConfig(config *publisher.Config) {
	if flag.Lookup("zonefilePath").Changed {
		config.ZonefilePath = *zonefilePath
	}
	if flag.Lookup("authServers").Changed {
		config.AuthServers = authServers.value
	}
	if flag.Lookup("privateKeyPath").Changed {
		config.PrivateKeyPath = *privateKeyPath
	}
	if flag.Lookup("keepShards").Changed {
		config.ShardingConf.KeepShards = *keepShards
	}
	if flag.Lookup("doSharding").Changed {
		config.ShardingConf.DoSharding = *doSharding
	}
	if flag.Lookup("nofAssertionsPerShard").Changed {
		config.ShardingConf.NofAssertionsPerShard = *nofAssertionsPerShard
	}
	if flag.Lookup("maxShardSize").Changed {
		config.ShardingConf.MaxShardSize = *maxShardSize
	}
	if flag.Lookup("keepPshards").Changed {
		config.PShardingConf.KeepPshards = *keepPshards
	}
	if flag.Lookup("doPsharding").Changed {
		config.PShardingConf.DoPsharding = *doPsharding
	}
	if flag.Lookup("nofAssertionsPerPshard").Changed {
		config.PShardingConf.NofAssertionsPerPshard = *nofAssertionsPerPshard
	}
	if flag.Lookup("bfAlgo").Changed {
		config.PShardingConf.BloomFilterConf.BFAlgo = bfAlgo.value
	}
	if flag.Lookup("bfHash").Changed {
		config.PShardingConf.BloomFilterConf.BFHash = bfHash.value
	}
	if flag.Lookup("bloomFilterSize").Changed {
		config.PShardingConf.BloomFilterConf.BloomFilterSize = *bloomFilterSize
	}
	if flag.Lookup("addSignatureMetaData").Changed {
		config.MetaDataConf.AddSignatureMetaData = *addSignatureMetaData
	}
	if flag.Lookup("addSigMetaDataToAssertions").Changed {
		config.MetaDataConf.AddSigMetaDataToAssertions = *addSigMetaDataToAssertions
	}
	if flag.Lookup("addSigMetaDataToShards").Changed {
		config.MetaDataConf.AddSigMetaDataToShards = *addSigMetaDataToShards
	}
	if flag.Lookup("addSigMetaDataToPshards").Changed {
		config.MetaDataConf.AddSigMetaDataToPshards = *addSigMetaDataToPshards
	}
	if flag.Lookup("signatureAlgorithm").Changed {
		config.MetaDataConf.SignatureAlgorithm = signatureAlgorithm.value
	}
	if flag.Lookup("keyPhase").Changed {
		config.MetaDataConf.KeyPhase = *keyPhase
	}
	if flag.Lookup("sigValidSince").Changed {
		config.MetaDataConf.SigValidSince = *sigValidSince
	}
	if flag.Lookup("sigValidUntil").Changed {
		config.MetaDataConf.SigValidUntil = *sigValidUntil
	}
	if flag.Lookup("sigSigningInterval").Changed {
		config.MetaDataConf.SigSigningInterval = time.Duration(*sigSigningInterval) * time.Second
	}
	if flag.Lookup("doConsistencyCheck").Changed {
		config.ConsistencyConf.DoConsistencyCheck = *doConsistencyCheck
	}
	if flag.Lookup("sortShards").Changed {
		config.ConsistencyConf.SortShards = *sortShards
	}
	if flag.Lookup("sortZone").Changed {
		config.ConsistencyConf.SortZone = *sortZone
	}
	if flag.Lookup("sigNotExpired").Changed {
		config.ConsistencyConf.SigNotExpired = *sigNotExpired
	}
	if flag.Lookup("checkStringFields").Changed {
		config.ConsistencyConf.CheckStringFields = *checkStringFields
	}
	if flag.Lookup("doSigning").Changed {
		config.DoSigning = *doSigning
	}
	if flag.Lookup("maxZoneSize").Changed {
		config.MaxZoneSize = *maxZoneSize
	}
	if flag.Lookup("outputPath").Changed {
		config.OutputPath = *outputPath
	}
	if flag.Lookup("doPublish").Changed {
		config.DoPublish = *doPublish
	}
}

type addressesFlag struct {
	set   bool
	value []connection.Info
}

func (i *addressesFlag) String() string {
	return fmt.Sprint("[]")
}

func (i *addressesFlag) Set(value string) error {
	var addresses []string
	addresses = strings.Split(value, ",")
	i.set = true
	for _, addr := range addresses {
		if tcpAddr, err := net.ResolveTCPAddr("tcp", addr); err == nil {
			i.value = append(i.value, connection.Info{Type: connection.TCP, Addr: tcpAddr})
		} else {
			return err
		}
	}
	return nil
}

func (i *addressesFlag) Type() string {
	return fmt.Sprint("[]net.Addr")
}

type bfHashFlag struct {
	set   bool
	value algorithmTypes.Hash
}

func (i *bfHashFlag) String() string {
	return fmt.Sprint("shake256")
}

func (i *bfHashFlag) Set(value string) error {
	switch value {
	case zonefile.TypeShake256, "shake256", "4":
		i.value = algorithmTypes.Shake256
		i.set = true
	case zonefile.TypeFnv64, "fnv64", "5":
		i.value = algorithmTypes.Fnv64
		i.set = true
	case zonefile.TypeFnv128, "fnv128", "6":
		i.value = algorithmTypes.Fnv128
		i.set = true
	default:
		return errors.New("unknown hash algorithm type")
	}
	return nil
}

func (i *bfHashFlag) Type() string {
	return fmt.Sprint("bfHash")
}

type algoFlag struct {
	set   bool
	value algorithmTypes.Signature
}

func (i *algoFlag) String() string {
	return fmt.Sprint("ed25519")
}

func (i *algoFlag) Set(value string) error {
	switch value {
	case zonefile.TypeEd25519, "ed25519", "1":
		i.set = true
		i.value = algorithmTypes.Ed25519
	default:
		return fmt.Errorf("invalid signature algorithm type")
	}
	return nil
}

func (i *algoFlag) Type() string {
	return fmt.Sprint("sigAlgo")
}

type bfAlgoFlag struct {
	set   bool
	value section.BloomFilterAlgo
}

func (i *bfAlgoFlag) String() string {
	return fmt.Sprint("bloomKM12")
}

func (i *bfAlgoFlag) Set(value string) error {
	switch value {
	case zonefile.TypeKM12, "bloomKM12", "0":
		i.set = true
		i.value = section.BloomKM12
	case zonefile.TypeKM16, "bloomKM16", "1":
		i.set = true
		i.value = section.BloomKM16
	case zonefile.TypeKM20, "bloomKM20", "2":
		i.set = true
		i.value = section.BloomKM20
	case zonefile.TypeKM24, "bloomKM24", "3":
		i.set = true
		i.value = section.BloomKM24
	default:
		return fmt.Errorf("invalid bloom filter mode of operation type")
	}
	return nil
}

func (i *bfAlgoFlag) Type() string {
	return fmt.Sprint("bfAlgo")
}
