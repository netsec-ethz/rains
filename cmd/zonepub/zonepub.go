package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	parser "github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"github.com/netsec-ethz/rains/internal/pkg/rainslib"
)

var configPath string
var zonefilePath = flag.String("zonefilePath", "", "Path to the zonefile")
var authServers addressesFlag
var privateKeyPath = flag.String("privateKeyPath", "", `Path to a file storing the private keys. 
Each line contains a key phase and a private key encoded in hexadecimal separated by a space.`)
var doSharding boolFlag
var keepExistingShards boolFlag
var nofAssertionsPerShard = flag.Int("nofAssertionsPerShard", -1, `Defines the number of assertions
per shard if sharding is performed`)
var maxShardSize = flag.Int("maxShardSize", -1, `this option only has an effect when DoSharding is 
true. Assertions are added to a shard until its size would become larger than maxShardSize. Then the
process is repeated with a new shard.`)
var doPsharding boolFlag
var keepExistingPshards boolFlag
var nofAssertionsPerPshard = flag.Int("nofAssertionsPerPshard", -1, `this option only has an effect
when doPsharding is true. Defines the number of assertions with different names per pshard if
sharding is performed. Because the number of assertions per name can vary, shards may have different
sizes.`)
var hashfamily hashFamilyFlag
var nofHashFunctions = flag.Int("nofHashFunctions", -1, `The number of hash functions used to add to
and query the bloom filter.`)
var bFOpMode bfOpModeFlag
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

var msgFramer rainslib.MsgFramer

func init() {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	flag.Var(&authServers, "authServers", `Authoritative server addresses to which the 
	sections in the zone file are forwarded.`)
	flag.Var(&doSharding, "doSharding", `If set to true, only assertions in the zonefile are 
	considered and grouped into shards based on configuration`)
	flag.Var(&keepExistingShards, "keepExistingShards", `this option only has an effect when 
	DoSharding is true. If the zonefile already contains shards and keepExistingShards is true, the 
	shards are kept. Otherwise, all existing shards are removed before the new ones are created.`)
	flag.Var(&doPsharding, "doPsharding", `If set to true, all assertions in the zonefile
	are grouped into pshards based on KeepExistingPshards, NofAssertionsPerPshard, Hashfamily,
	NofHashFunctions, BFOpMode, and BloomFilterSize parameters.`)
	flag.Var(&keepExistingPshards, "keepExistingPshards", `this option only has an effect when 
	DoPsharding is true. If the zonefile already contains pshards and keepExistingPshards is true,
	the pshards are kept. Otherwise, all existing pshards are removed before the new ones are
	created.`)
	flag.Var(&hashfamily, "hashfamily", `A list of hash algorithm identifiers present in the hash
	family.`)
	flag.Var(&bFOpMode, "bfOpModeFlag", `Bloom filter's mode of operation`)
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
	config, err := loadConfig(flag.Args()[0])
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
	if doSharding.set {
		config.ShardingConf.DoSharding = doSharding.value
	}
	if keepExistingShards.set {
		config.ShardingConf.KeepExistingShards = keepExistingShards.value
	}
	if *nofAssertionsPerShard != -1 {
		config.ShardingConf.NofAssertionsPerShard = *nofAssertionsPerShard
	}
	if *maxShardSize != -1 {
		config.ShardingConf.MaxShardSize = *maxShardSize
	}
	if doPsharding.set {
		config.PShardingConf.DoPsharding = doPsharding.value
	}
	if keepExistingPshards.set {
		config.PShardingConf.KeepExistingPshards = keepExistingPshards.value
	}
	if *nofAssertionsPerPshard != -1 {
		config.PShardingConf.NofAssertionsPerPshard = *nofAssertionsPerPshard
	}
	if hashfamily.set {
		config.PShardingConf.BloomFilterConf.Hashfamily = hashfamily.value
	}
	if *nofHashFunctions != -1 {
		config.PShardingConf.BloomFilterConf.NofHashFunctions = *nofHashFunctions
	}
	if bFOpMode.set {
		config.PShardingConf.BloomFilterConf.BFOpMode = bFOpMode.value
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
		config.MetaDataConf.SigValidSince = time.Duration(*sigValidSince) * time.Second
	}
	if *sigValidUntil != -1 {
		config.MetaDataConf.SigValidUntil = time.Duration(*sigValidUntil) * time.Second
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

//loadConfig loads configuration information from configPath
func loadConfig(configPath string) (publisher.Config, error) {
	var config publisher.Config
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error("Could not open config file...", "path", configPath, "error", err)
		return publisher.Config{}, err
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Error("Could not unmarshal json format of config", "error", err)
		return publisher.Config{}, err
	}
	config.MetaDataConf.SigValidSince *= time.Second
	config.MetaDataConf.SigValidUntil *= time.Second
	config.MetaDataConf.SigSigningInterval *= time.Second
	return config, nil
}

type addressesFlag struct {
	set   bool
	value []rainslib.ConnInfo
}

func (i *addressesFlag) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *addressesFlag) Set(value string) error {
	var addresses []string
	addresses = strings.Split(value, ",")
	i.set = true
	for _, addr := range addresses {
		if tcpAddr, err := net.ResolveTCPAddr("tcp", addr); err == nil {
			i.value = append(i.value, rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr})
		} else {
			return err
		}
	}
	return nil
}

type hashFamilyFlag struct {
	set   bool
	value []rainslib.HashAlgorithmType
}

func (i *hashFamilyFlag) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *hashFamilyFlag) Set(value string) error {
	var algos []string
	algos = strings.Split(value, ",")
	i.set = true
	for _, algo := range algos {
		switch algo {
		case parser.TypeSha256:
			i.value = append(i.value, rainslib.Sha256)
		case parser.TypeSha384:
			i.value = append(i.value, rainslib.Sha384)
		case parser.TypeSha512:
			i.value = append(i.value, rainslib.Sha512)
		case parser.TypeFnv64:
			i.value = append(i.value, rainslib.Fnv64)
		case parser.TypeMurmur364:
			i.value = append(i.value, rainslib.Murmur364)
		default:
			return errors.New("unknown hash algorithm type")
		}
	}
	return nil
}

type algorithmFlag struct {
	set   bool
	value rainslib.SignatureAlgorithmType
}

func (i *algorithmFlag) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *algorithmFlag) Set(value string) error {
	switch value {
	case parser.TypeEd25519, "ed25519", "1":
		i.set = true
		i.value = rainslib.Ed25519
	default:
		return fmt.Errorf("invalid signature algorithm type")
	}
	return nil
}

type bfOpModeFlag struct {
	set   bool
	value rainslib.ModeOfOperationType
}

func (i *bfOpModeFlag) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *bfOpModeFlag) Set(value string) error {
	switch value {
	case parser.TypeStandard, "standard", "0":
		i.set = true
		i.value = rainslib.StandardOpType
	case parser.TypeKM1, "km1", "1":
		i.set = true
		i.value = rainslib.KirschMitzenmacher1
	case parser.TypeKM2, "km2", "2":
		i.set = true
		i.value = rainslib.KirschMitzenmacher2
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
	if isTrue(value) {
		i.set = true
		i.value = true
		return nil
	}
	if isFalse(value) {
		i.set = true
		return nil
	}
	return fmt.Errorf("invalid boolean value")
}

//isTrue returns true if a boolean flag is either true, True, TRUE, T, t or 1 (as in the flag
//package)
func isTrue(v string) bool {
	return v == "true" || v == "True" || v == "TRUE" || v == "1" || v == "T" || v == "t"
}

//isFalse returns true if a boolean flag is either false, False, FALSE, F, f, 0 (as in the flag
//package)
func isFalse(v string) bool {
	return v == "false" || v == "False" || v == "FALSE" || v == "0" || v == "F" || v == "f"
}
