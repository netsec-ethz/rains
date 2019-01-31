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
	"github.com/spf13/cobra"
)

var config = publisher.DefaultConfig()
var zonefilePath string
var authServers addressesFlag
var privateKeyPath string
var doSharding bool
var keepShards bool
var nofAssertionsPerShard int
var maxShardSize int
var doPsharding bool
var keepPshards bool
var nofAssertionsPerPshard int
var bfAlgo bfAlgoFlag
var bfHash bfHashFlag
var bloomFilterSize int
var addSignatureMetaData bool
var addSigMetaDataToAssertions bool
var addSigMetaDataToShards bool
var addSigMetaDataToPshards bool
var signatureAlgorithm algoFlag
var keyPhase int
var sigValidSince int64
var sigValidUntil int64
var sigSigningInterval int64
var doConsistencyCheck bool
var sortShards bool
var sortZone bool
var sigNotExpired bool
var checkStringFields bool
var doSigning bool
var maxZoneSize int
var outputPath string
var doPublish bool

var rootCmd = &cobra.Command{
	Use:   "zonepub [PATH]",
	Short: "zonepub is a tool to publish zone information",
	Long: `	zonepub (short for zone publisher) is a tool for pushing sections to RAINS
	servers from the command line. It reads a zone file and sends it to all
	authoritative RAINS servers specified in the config file. If no PATH to a
	config file is provided, the default config is used.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 {
			var err error
			if config, err = publisher.LoadConfig(args[0]); err != nil {
				log.Fatalf("Error: was not able to load config file: %v", err)
			}
		}
	},
}

func init() {
	rootCmd.Flags().Var(&authServers, "authServers", "Authoritative server addresses to which the sections "+
		"in the zone file are forwarded.")
	rootCmd.Flags().Var(&bfAlgo, "bfAlgo", "Bloom filter's algorithm.")
	rootCmd.Flags().Var(&bfHash, "bfHash", "Hash algorithm used to add to or check bloomfilter.")
	rootCmd.Flags().Var(&signatureAlgorithm, "signatureAlgorithm", "this option only has an "+
		"effect when addSignatureMetaData is true. Defines which algorithm will be used for signing. "+
		"Together with keyPhase this uniquely defines which private key will be used.")
	rootCmd.Flags().StringVar(&zonefilePath, "zonefilePath", "data/zonefiles/zf.txt", "Path to the zonefile")
	rootCmd.Flags().StringVar(&privateKeyPath, "privateKeyPath", "data/keys/key_sec.pem", "Path to a file storing the private keys. "+
		"Each line contains a key phase as integer and a private key encoded in hexadecimal separated by a space.")
	rootCmd.Flags().BoolVar(&doSharding, "doSharding", true, "If set to true, all assertions in the zonefile "+
		"are grouped into pshards based on keepPshards, nofAssertionsPerPshard, bFAlgo, BFHash, and "+
		"bloomFilterSize parameters.")
	rootCmd.Flags().BoolVar(&keepShards, "keepShards", false, "this option only has an effect when DoSharding "+
		"is true. If the zonefile already contains shards, they are kept. Otherwise, all existing "+
		"shards are removed before the new ones are created.")

	rootCmd.Flags().IntVar(&nofAssertionsPerShard, "nofAssertionsPerShard", -1,
		"this option only has an effect when DoSharding is true. Defines the number of assertions per shard")
	rootCmd.Flags().IntVar(&maxShardSize, "maxShardSize", 1000, "this option only has an effect when DoSharding is "+
		"true. Assertions are added to a shard until its size would become larger than maxShardSize in "+
		"bytes. Then the process is repeated with a new shard.")
	rootCmd.Flags().BoolVar(&doPsharding, "doPsharding", true, "If set to true, all assertions in the zonefile "+
		"are grouped into pshards based on keepPshards, nofAssertionsPerPshard, bFAlgo, BFHash, and "+
		"bloomFilterSize parameters.")
	rootCmd.Flags().BoolVar(&keepPshards, "keepPshards", false, "this option only has an effect when "+
		"DoPsharding is true. If the zonefile already contains pshards, they are kept. "+
		"Otherwise, all existing pshards are removed before the new ones are created.")

	rootCmd.Flags().IntVar(&nofAssertionsPerPshard, "nofAssertionsPerPshard", 50, "this option only has an effect"+
		"when doPsharding is true. Defines the number of assertions with different names per pshard.")
	rootCmd.Flags().IntVar(&bloomFilterSize, "bloomFilterSize", 200, "Number of bytes in the bloom filter.")
	rootCmd.Flags().BoolVar(&addSignatureMetaData, "addSignatureMetaData", true, "If set to true, adds "+
		"signature meta data to sections")
	rootCmd.Flags().BoolVar(&addSigMetaDataToAssertions, "addSigMetaDataToAssertions", true, "this option "+
		"only has an effect when AddSignatureMetaData is true. If set to true, signature meta data is "+
		"added to all assertions contained in a shard or zone.")
	rootCmd.Flags().BoolVar(&addSigMetaDataToShards, "addSigMetaDataToShards", true, "this option only has "+
		"an effect when AddSignatureMetaData is true. If set to true, signature meta data is added to "+
		"all shards contained the zone.")
	rootCmd.Flags().BoolVar(&addSigMetaDataToPshards, "addSigMetaDataToPshards", true, "this option only "+
		"has an effect when AddSignatureMetaData is true. If set to true, signature meta data is added "+
		"to all pshards contained the zone.")
	rootCmd.Flags().IntVar(&keyPhase, "keyPhase", 0, "this option only has an effect when addSignatureMetaData "+
		"is true. Defines the key phase in which the sections will be signed. Together with KeyPhase this "+
		"uniquely defines which private key will be used. (default 0)")
	rootCmd.Flags().Int64Var(&sigValidSince, "sigValidSince", 0, "this option only has an effect when "+
		"addSignatureMetaData is true. Defines the starting point of the SigSigningInterval for the Signature "+
		"validSince values. Assertions' validSince values are uniformly spread out over this interval. "+
		"Value must be an int64 representing unix seconds since 1.1.1970. (default current time)")
	rootCmd.Flags().Int64Var(&sigValidUntil, "sigValidUntil", -1, "this option only has an effect when "+
		"addSignatureMetaData is true. Defines the starting point of the SigSigningInterval for the "+
		"Signature validUntil values. Assertions' validUntil values are uniformly spread out over this "+
		"interval. Value must be an int64 representing unix seconds since 1.1.1970 (default current "+
		"time plus 24 hours)")
	rootCmd.Flags().Int64Var(&sigSigningInterval, "sigSigningInterval", 0, "this option only has an effect when "+
		"addSignatureMetaData is true. Defines the time interval in seconds over which the assertions' "+
		"signature lifetimes are uniformly spread out. (default 1 minute)")
	rootCmd.Flags().BoolVar(&doConsistencyCheck, "doConsistencyCheck", true, "Performs all consistency checks "+
		"if set to true. The check involves: sorting shards, sorting zones, checking that no signature "+
		"is expired, and that all string fields contain no protocol keywords.")
	rootCmd.Flags().BoolVar(&sortShards, "sortShards", false, "If set to true, makes sure that the assertions "+
		"withing the shard are sorted.")
	rootCmd.Flags().BoolVar(&sortZone, "sortZone", false, "If set to true, makes sure that the assertions "+
		"withing the zone are sorted.")
	rootCmd.Flags().BoolVar(&sigNotExpired, "sigNotExpired", false, "If set to true, checks that all signatures "+
		"have a validUntil time in the future")
	rootCmd.Flags().BoolVar(&checkStringFields, "checkStringFields", false, "If set to true, checks that none "+
		"of the assertions' text fields contain protocol keywords.")
	rootCmd.Flags().BoolVar(&doSigning, "doSigning", true, "If set to true, all sections with signature meta "+
		"data are signed.")
	rootCmd.Flags().IntVar(&maxZoneSize, "maxZoneSize", 60000, "this option only has an effect when doSigning is "+
		"true. If the zone's size is larger than maxZoneSize then only the zone's content is signed but "+
		"not the zone itself.")
	rootCmd.Flags().StringVar(&outputPath, "outputPath", "", "If not an empty string, a zonefile with the signed "+
		"sections is generated and stored at the provided path. (default \"\")")
	rootCmd.Flags().BoolVar(&doPublish, "doPublish", true, "If set to true, sends the signed sections to all "+
		"authoritative rains servers. If the zone is smaller than the maximum allowed size, the zone is "+
		"sent. Otherwise, the zone section's content is sent separately such that the maximum message "+
		"size is not exceeded.")
}

//main initializes rainspub
func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
	if !rootCmd.Flag("help").Changed {
		updateConfig(&config)
		server := publisher.New(config)
		if err := server.Publish(); err != nil {
			log.Fatalf("Publishing to server [%v] failed: %v", config.AuthServers, err)
		}
	}
}

//updateConfig overrides config with the provided cmd line flags
func updateConfig(config *publisher.Config) {
	if rootCmd.Flag("zonefilePath").Changed {
		config.ZonefilePath = zonefilePath
	}
	if rootCmd.Flag("authServers").Changed {
		config.AuthServers = authServers.value
	}
	if rootCmd.Flag("privateKeyPath").Changed {
		config.PrivateKeyPath = privateKeyPath
	}
	if rootCmd.Flag("keepShards").Changed {
		config.ShardingConf.KeepShards = keepShards
	}
	if rootCmd.Flag("doSharding").Changed {
		config.ShardingConf.DoSharding = doSharding
	}
	if rootCmd.Flag("nofAssertionsPerShard").Changed {
		config.ShardingConf.NofAssertionsPerShard = nofAssertionsPerShard
	}
	if rootCmd.Flag("maxShardSize").Changed {
		config.ShardingConf.MaxShardSize = maxShardSize
	}
	if rootCmd.Flag("keepPshards").Changed {
		config.PShardingConf.KeepPshards = keepPshards
	}
	if rootCmd.Flag("doPsharding").Changed {
		config.PShardingConf.DoPsharding = doPsharding
	}
	if rootCmd.Flag("nofAssertionsPerPshard").Changed {
		config.PShardingConf.NofAssertionsPerPshard = nofAssertionsPerPshard
	}
	if rootCmd.Flag("bfAlgo").Changed {
		config.PShardingConf.BloomFilterConf.BFAlgo = bfAlgo.value
	}
	if rootCmd.Flag("bfHash").Changed {
		config.PShardingConf.BloomFilterConf.BFHash = bfHash.value
	}
	if rootCmd.Flag("bloomFilterSize").Changed {
		config.PShardingConf.BloomFilterConf.BloomFilterSize = bloomFilterSize
	}
	if rootCmd.Flag("addSignatureMetaData").Changed {
		config.MetaDataConf.AddSignatureMetaData = addSignatureMetaData
	}
	if rootCmd.Flag("addSigMetaDataToAssertions").Changed {
		config.MetaDataConf.AddSigMetaDataToAssertions = addSigMetaDataToAssertions
	}
	if rootCmd.Flag("addSigMetaDataToShards").Changed {
		config.MetaDataConf.AddSigMetaDataToShards = addSigMetaDataToShards
	}
	if rootCmd.Flag("addSigMetaDataToPshards").Changed {
		config.MetaDataConf.AddSigMetaDataToPshards = addSigMetaDataToPshards
	}
	if rootCmd.Flag("signatureAlgorithm").Changed {
		config.MetaDataConf.SignatureAlgorithm = signatureAlgorithm.value
	}
	if rootCmd.Flag("keyPhase").Changed {
		config.MetaDataConf.KeyPhase = keyPhase
	}
	if rootCmd.Flag("sigValidSince").Changed {
		config.MetaDataConf.SigValidSince = sigValidSince
	}
	if rootCmd.Flag("sigValidUntil").Changed {
		config.MetaDataConf.SigValidUntil = sigValidUntil
	}
	if rootCmd.Flag("sigSigningInterval").Changed {
		config.MetaDataConf.SigSigningInterval = time.Duration(sigSigningInterval) * time.Second
	}
	if rootCmd.Flag("doConsistencyCheck").Changed {
		config.ConsistencyConf.DoConsistencyCheck = doConsistencyCheck
	}
	if rootCmd.Flag("sortShards").Changed {
		config.ConsistencyConf.SortShards = sortShards
	}
	if rootCmd.Flag("sortZone").Changed {
		config.ConsistencyConf.SortZone = sortZone
	}
	if rootCmd.Flag("sigNotExpired").Changed {
		config.ConsistencyConf.SigNotExpired = sigNotExpired
	}
	if rootCmd.Flag("checkStringFields").Changed {
		config.ConsistencyConf.CheckStringFields = checkStringFields
	}
	if rootCmd.Flag("doSigning").Changed {
		config.DoSigning = doSigning
	}
	if rootCmd.Flag("maxZoneSize").Changed {
		config.MaxZoneSize = maxZoneSize
	}
	if rootCmd.Flag("outputPath").Changed {
		config.OutputPath = outputPath
	}
	if rootCmd.Flag("doPublish").Changed {
		config.DoPublish = doPublish
	}
}

type addressesFlag struct {
	set   bool
	value []connection.Info
}

func (i *addressesFlag) String() string {
	if i.set {
		return fmt.Sprintf("%v", i.value)
	}
	return "[]" //default
}

func (i *addressesFlag) Set(value string) error {
	var addresses []string
	addresses = strings.Split(value, ",")
	for _, addr := range addresses {
		if tcpAddr, err := net.ResolveTCPAddr("tcp", addr); err == nil {
			i.value = append(i.value, connection.Info{Type: connection.TCP, Addr: tcpAddr})
		} else {
			return err
		}
	}
	i.set = true
	return nil
}

func (i *addressesFlag) Type() string {
	return "[]net.Addr"
}

type bfHashFlag struct {
	set   bool
	value algorithmTypes.Hash
}

func (i *bfHashFlag) String() string {
	if i.set {
		return i.value.String()
	}
	return "shake256" //default
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
	return "BloomFilterHash"
}

type algoFlag struct {
	set   bool
	value algorithmTypes.Signature
}

func (i *algoFlag) String() string {
	if i.set {
		return i.value.String()
	}
	return "ed25519" //default
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
	return "SignatureAlgo"
}

type bfAlgoFlag struct {
	set   bool
	value section.BloomFilterAlgo
}

func (i *bfAlgoFlag) String() string {
	if i.set {
		return i.value.String()
	}
	return "bloomKM12" //default
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
	return "BloomFilterAlgo"
}
