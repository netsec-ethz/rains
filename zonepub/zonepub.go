package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/rainspub"
)

var configPath string
var zonefilePath = flag.String("zonefilePath", "", "Path to the zonefile")
var authServers addressesFlag
var privateKeyPath = flag.String("privateKeyPath", "", `Path to a file storing the private keys. 
Each line contains a key phase and a private key encoded in hexadecimal separated by a space.`)
var doSharding boolFlag
var nofAssertionsPerShard = flag.Int("nofAssertionsPerShard", -1, `Defines the number of assertions
per shard if sharding is performed`)
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
var signAssertions boolFlag
var signShards boolFlag
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
	flag.Var(&addSignatureMetaData, "addSignatureMetaData", `If set to true, adds signature meta 
	data to sections`)
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
	flag.Var(&signAssertions, "signAssertions", "If set, signs all assertions")
	flag.Var(&signShards, "signShards", "If set, signs all shards")
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
		config.DoSharding = doSharding.value
	}
	if *nofAssertionsPerShard != -1 {
		config.NofAssertionsPerShard = *nofAssertionsPerShard
	}
	if addSignatureMetaData.set {
		config.AddSignatureMetaData = addSignatureMetaData.value
	}
	if signatureAlgorithm.set {
		config.SignatureAlgorithm = signatureAlgorithm.value
	}
	if *keyPhase != -1 {
		config.KeyPhase = *keyPhase
	}
	if *sigValidSince != -1 {
		config.SigValidSince = time.Duration(*sigValidSince) * time.Second
	}
	if *sigValidUntil != -1 {
		config.SigValidUntil = time.Duration(*sigValidUntil) * time.Second
	}
	if *sigSigningInterval != -1 {
		config.SigSigningInterval = time.Duration(*sigSigningInterval) * time.Second
	}
	if doConsistencyCheck.set {
		config.DoConsistencyCheck = doConsistencyCheck.value
	}
	if sortShards.set {
		config.SortShards = sortShards.value
	}
	if sigNotExpired.set {
		config.SigNotExpired = sigNotExpired.value
	}
	if checkStringFields.set {
		config.CheckStringFields = checkStringFields.value
	}
	if doSigning.set {
		config.DoSigning = doSigning.value
	}
	if signAssertions.set {
		config.SignAssertions = signAssertions.value
	}
	if signShards.set {
		config.SignShards = signShards.value
	}
	if *outputPath != "" {
		config.OutputPath = *outputPath
	}
	if doPublish.set {
		config.DoPublish = doPublish.value
	}

	//Call rainspub to do the work according to the updated config
	rainspub.Init(config)
}

//loadConfig loads configuration information from configPath
func loadConfig(configPath string) (rainspub.Config, error) {
	var config rainspub.Config
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error("Could not open config file...", "path", configPath, "error", err)
		return rainspub.Config{}, err
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Error("Could not unmarshal json format of config", "error", err)
		return rainspub.Config{}, err
	}
	config.SigValidSince *= time.Second
	config.SigValidUntil *= time.Second
	config.SigSigningInterval *= time.Second
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

type algorithmFlag struct {
	set   bool
	value rainslib.SignatureAlgorithmType
}

func (i *algorithmFlag) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *algorithmFlag) Set(value string) error {
	switch value {
	case ":ed25519:", "ed25519", "1":
		i.set = true
		i.value = rainslib.Ed25519
	default:
		return fmt.Errorf("invalid signature algorithm type")
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
