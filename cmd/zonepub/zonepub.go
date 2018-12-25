package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

var configPath string
var zonefilePath = flag.String("zonefilePath", "", "Path to the zonefile")
var authServers addressesFlag
var privateKeyPath = flag.String("privateKeyPath", "", `Path to a file storing the private keys. 
Each line contains a key phase and a private key encoded in hexadecimal separated by a space.`)
var includeShards boolFlag
var doSharding boolFlag
var nofAssertionsPerShard = flag.Int("nofAssertionsPerShard", -1, `Defines the number of assertions
per shard if sharding is performed`)
var maxShardSize = flag.Int("maxShardSize", -1, `this option only has an effect when DoSharding is 
true. Assertions are added to a shard until its size would become larger than maxShardSize. Then the
process is repeated with a new shard.`)
var includePshards boolFlag
var doPsharding boolFlag
var nofAssertionsPerPshard = flag.Int("nofAssertionsPerPshard", -1, `this option only has an effect
when doPsharding is true. Defines the number of assertions with different names per pshard if
sharding is performed. Because the number of assertions per name can vary, shards may have different
sizes.`)
var bfHash bfHashFlag
var bfAlgo bfAlgoFlag
var bloomFilterSize = flag.Int("bloomFilterSize", -1, `Number of bits in the bloom filter. It will
be rounded up to the next multiple of eight.`)
var addSignatureMetaData boolFlag
var signatureAlgorithm algorithmFlag
var keyPhase = flag.Int("keyPhase", -1, "Defines which private key is used for signing")
var sigValidSince = flag.Int64("sigValidSince", -1, `Defines the starting point of the 
SigSigningInterval for the Signature validSince values. Assertions' validSince values are uniformly
spread out over this interval. Value must be an int64 representing unix seconds since 1.1.1970`)
var sigValidUntil = flag.Int64("sigValidUntil", -1, `Defines the starting point of the 
SigSigningInterval for the Signature validUntil values. Assertions' validUntil values are uniformly
spread out over this interval. Value must be an int64 representing unix seconds since 1.1.1970`)
var sigSigningInterval = flag.Int64("sigSigningInterval", -1, `Defines the time interval in seconds 
over which the assertions' signature lifetimes are uniformly spread out.`)
var doConsistencyCheck boolFlag
var sortShards boolFlag
var sortZone boolFlag
var sigNotExpired boolFlag
var checkStringFields boolFlag
var doSigning boolFlag
var maxZoneSize = flag.Int("maxZoneSize", -1, `this option only has an effect when DoSigning is
true. If the zone's size is larger than MaxZoneSize then only the zone's content is signed but not
the zone itself.`)
var addSigMetaDataToAssertions boolFlag
var addSigMetaDataToShards boolFlag
var addSigMetaDataToPshards boolFlag
var outputPath = flag.String("outputPath", "", `If set, a zonefile with the signed sections is 
generated and stored at the provided path`)
var doPublish boolFlag

func init() {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	flag.Var(&authServers, "authServers", `Authoritative server addresses to which the 
	sections in the zone file are forwarded.`)
	flag.Var(&includeShards, "includeShards", `If set to true, only assertions in the zonefile are 
	considered and grouped into shards based on configuration`)
	flag.Var(&doSharding, "keepExistingShards", `this option only has an effect when 
	DoSharding is true. If the zonefile already contains shards and keepExistingShards is true, the 
	shards are kept. Otherwise, all existing shards are removed before the new ones are created.`)
	flag.Var(&includePshards, "doPsharding", `If set to true, all assertions in the zonefile
	are grouped into pshards based on KeepExistingPshards, NofAssertionsPerPshard, Hashfamily,
	NofHashFunctions, BFOpMode, and BloomFilterSize parameters.`)
	flag.Var(&doPsharding, "keepExistingPshards", `this option only has an effect when 
	DoPsharding is true. If the zonefile already contains pshards and keepExistingPshards is true,
	the pshards are kept. Otherwise, all existing pshards are removed before the new ones are
	created.`)
	flag.Var(&bfHash, "bfhash", `Hash algorithm used to add to or check bloomfilter`)
	flag.Var(&bfAlgo, "bfAlgo", `Bloom filter's algorithm`)
	flag.Var(&addSignatureMetaData, "addSignatureMetaData", `If set to true, adds signature meta 
	data to sections`)
	flag.Var(&addSigMetaDataToAssertions, "addSigMetaDataToAssertions", `this option only has an
	effect when AddSignatureMetaData is true. If set to true, signature meta data is added to all 
	assertions contained in a shard or zone.`)
	flag.Var(&addSigMetaDataToShards, "addSigMetaDataToShards", `this option only has an effect when
	AddSignatureMetaData is true. If set to true, signature meta data is added to all shards
	contained the zone.`)
	flag.Var(&addSigMetaDataToPshards, "addSigMetaDataToPshards", `this option only has an effect
	when AddSignatureMetaData is true. If set to true, signature meta data is added to all pshards
	contained the zone.`)
	flag.Var(&signatureAlgorithm, "signatureAlgorithm", "Algorithm to be used for signing")
	flag.Var(&doConsistencyCheck, "doConsistencyCheck", `Performs all consistency checks if set to 
	true. The check involves: TODO CFE`)
	flag.Var(&sortShards, "sortShards", `If set, makes sure that the assertions withing the shard 
	are sorted.`)
	flag.Var(&sortZone, "sortZone", `If set, makes sure that the assertions withing the zone 
	are sorted.`)
	flag.Var(&sigNotExpired, "sigNotExpired", `If set, checks that all signatures have a validUntil
	time in the future`)
	flag.Var(&checkStringFields, "checkStringFields", `If set, checks that none of the assertions' 
	text fields contain	type markers which are part of the protocol syntax (TODO CFE use more
	precise	vocabulary)`)
	flag.Var(&doSigning, "doSigning", "If set, signs all assertions and shards")
	flag.Var(&doPublish, "doPublish", `If set, sends the signed sections to all authoritative rainsd
	servers`)
	flag.Parse()
}

//main initializes rainspub
func main() {
	if flag.NArg() != 1 {
		log.Error("Wrong number of arguments, expected 1 (configPath) after the flags",
			"Got", flag.NArg())
	}
	config, err := publisher.LoadConfig(flag.Args()[0])
	if err != nil {
		return
	}
	//Overwrite config with provided cmd line flags
	if *zonefilePath != "" {
		config.ZonefilePath = *zonefilePath
	}
	if authServers.set {
		config.AuthServers = authServers.value
	}
	if *privateKeyPath != "" {
		config.PrivateKeyPath = *privateKeyPath
	}
	if includeShards.set {
		config.ShardingConf.IncludeShards = includeShards.value
	}
	if doSharding.set {
		config.ShardingConf.DoSharding = doSharding.value
	}
	if *nofAssertionsPerShard != -1 {
		config.ShardingConf.NofAssertionsPerShard = *nofAssertionsPerShard
	}
	if *maxShardSize != -1 {
		config.ShardingConf.MaxShardSize = *maxShardSize
	}
	if includePshards.set {
		config.PShardingConf.IncludePshards = includePshards.value
	}
	if doPsharding.set {
		config.PShardingConf.DoPsharding = doPsharding.value
	}
	if *nofAssertionsPerPshard != -1 {
		config.PShardingConf.NofAssertionsPerPshard = *nofAssertionsPerPshard
	}
	if bfAlgo.set {
		config.PShardingConf.BloomFilterConf.BFAlgo = bfAlgo.value
	}
	if bfHash.set {
		config.PShardingConf.BloomFilterConf.BFHash = bfHash.value
	}
	if *bloomFilterSize != -1 {
		config.PShardingConf.BloomFilterConf.BloomFilterSize = *bloomFilterSize
	}
	if addSignatureMetaData.set {
		config.MetaDataConf.AddSignatureMetaData = addSignatureMetaData.value
	}
	if addSigMetaDataToAssertions.set {
		config.MetaDataConf.AddSigMetaDataToAssertions = addSigMetaDataToAssertions.value
	}
	if addSigMetaDataToShards.set {
		config.MetaDataConf.AddSigMetaDataToShards = addSigMetaDataToShards.value
	}
	if addSigMetaDataToPshards.set {
		config.MetaDataConf.AddSigMetaDataToPshards = addSigMetaDataToPshards.value
	}
	if signatureAlgorithm.set {
		config.MetaDataConf.SignatureAlgorithm = signatureAlgorithm.value
	}
	if *keyPhase != -1 {
		config.MetaDataConf.KeyPhase = *keyPhase
	}
	if *sigValidSince != -1 {
		config.MetaDataConf.SigValidSince = *sigValidSince
	}
	if *sigValidUntil != -1 {
		config.MetaDataConf.SigValidUntil = *sigValidUntil
	}
	if *sigSigningInterval != -1 {
		config.MetaDataConf.SigSigningInterval = time.Duration(*sigSigningInterval) * time.Second
	}
	if doConsistencyCheck.set {
		config.ConsistencyConf.DoConsistencyCheck = doConsistencyCheck.value
	}
	if sortShards.set {
		config.ConsistencyConf.SortShards = sortShards.value
	}
	if sortZone.set {
		config.ConsistencyConf.SortZone = sortZone.value
	}
	if sigNotExpired.set {
		config.ConsistencyConf.SigNotExpired = sigNotExpired.value
	}
	if checkStringFields.set {
		config.ConsistencyConf.CheckStringFields = checkStringFields.value
	}
	if doSigning.set {
		config.DoSigning = doSigning.value
	}
	if *maxZoneSize != -1 {
		config.MaxZoneSize = *maxZoneSize
	}
	if *outputPath != "" {
		config.OutputPath = *outputPath
	}
	if doPublish.set {
		config.DoPublish = doPublish.value
	}

	//Call rainspub to do the work according to the updated config
	server := publisher.New(config)
	server.Publish()
}

type addressesFlag struct {
	set   bool
	value []net.Addr
}

func (i *addressesFlag) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *addressesFlag) Set(value string) error {
	var addresses []string
	addresses = strings.Split(value, ",")
	i.set = true
	for _, addr := range addresses {
		if tcpAddr, err := net.ResolveTCPAddr("tcp", addr); err == nil {
			i.value = append(i.value, tcpAddr)
		} else {
			return err
		}
	}
	return nil
}

type bfHashFlag struct {
	set   bool
	value algorithmTypes.Hash
}

func (i *bfHashFlag) String() string {
	return fmt.Sprintf("%v", *i)
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

type algorithmFlag struct {
	set   bool
	value algorithmTypes.Signature
}

func (i *algorithmFlag) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *algorithmFlag) Set(value string) error {
	switch value {
	case zonefile.TypeEd25519, "ed25519", "1":
		i.set = true
		i.value = algorithmTypes.Ed25519
	default:
		return fmt.Errorf("invalid signature algorithm type")
	}
	return nil
}

type bfAlgoFlag struct {
	set   bool
	value section.BloomFilterAlgo
}

func (i *bfAlgoFlag) String() string {
	return fmt.Sprintf("%v", *i)
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

type boolFlag struct {
	set   bool
	value bool
}

func (i *boolFlag) String() string {
	return fmt.Sprint(i.value)
}

func (i *boolFlag) Set(value string) error {
	input, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("invalid boolean value")
	}
	i.set = true
	i.value = input
	return nil
}
