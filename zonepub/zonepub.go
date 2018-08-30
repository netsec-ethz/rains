package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
)

var configPath string
var zonefilePath = flag.String("zoneFilePath", "", "Path to the zonefile")
var authServers addressesFlag
var privateKeyPath = flag.String("privateKeyPath", "", `Path to a file storing the private keys. 
Each line contains a key phase and a private key encoded in hexadecimal separated by a space.`)
var doSharding boolFlag
var nofAssertionsPerShard = flag.Int("nofAssertionsPerShard", -1, `Defines the number of assertions
per shard if sharding is performed`)
var addSignatureMetaData boolFlag

//var signatureAlgorithm=flag.
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
var outputFilePath boolFlag
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
	flag.Var(&outputFilePath, "outputFilePath", `If set, a zonefile with the signed sections is 
	generated and stored at the provided path`)
	flag.Var(&doPublish, "doPublish", `If set, sends the signed sections to all authoritative rainsd
	servers`)
	flag.Parse()
}

//main initializes rainspub
func main() {
	log.Info("", "", doSharding.set)
	/*err := loadConfig(configPath)
	if err != nil {
		return
	}*/
	/*parser = zoneFileParser.Parser{}
	for i, path := range config.ZonePrivateKeyPath {
		keyPhaseToPath[i] = path
	}*/
}

/*
//loadConfig loads configuration information from configPath
func loadConfig(configPath string) error {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error("Could not open config file...", "path", configPath, "error", err)
		return err
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Error("Could not unmarshal json format of config", "error", err)
		return err
	}
	config.AssertionValidSince *= time.Hour
	config.ShardValidSince *= time.Hour
	config.ZoneValidSince *= time.Hour
	config.DelegationValidSince *= time.Hour
	config.AssertionValidUntil *= time.Hour
	config.ShardValidUntil *= time.Hour
	config.ZoneValidUntil *= time.Hour
	config.DelegationValidUntil *= time.Hour
	return nil
}

// InitFromFlags initializes the rainspub instance from flags instead
// of command line parameters.
func InitFromFlags(serverHost, zoneFile, privateKeyFile string, validityDuration time.Duration, serverPort int) error {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	config.ZoneFilePath = zoneFile
	config.ZonePrivateKeyPath = []string{privateKeyFile}
	config.ServerAddresses = make([]rainslib.ConnInfo, 0)
	config.ServerAddresses = append(config.ServerAddresses, rainslib.ConnInfo{
		Type: rainslib.TCP,
		TCPAddr: &net.TCPAddr{
			IP:   net.ParseIP(serverHost),
			Port: serverPort,
		},
	})
	config.ZoneValidUntil = validityDuration
	config.DelegationValidUntil = validityDuration
	config.AssertionValidUntil = validityDuration
	p := zoneFileParser.Parser{}
	parser = p
	return nil
}

//publishZone performs the following steps:
//1) Loads the rains zone file.
//2) Adds Signature MetaData and perform consistency checks on the zone and its
//   signatures
//3) Let rainspub sign the zone
//4) Query the superordinate zone for the new delegation and push it to all
//   rains servers
//5) After rainspub signed the zone, send the signed zone to all rains servers
//   specified in the config
//returns an error if something goes wrong
func publishZone(keyPhase int) error {
	file, err := ioutil.ReadFile(config.ZoneFilePath)
	if err != nil {
		log.Error("Was not able to read zone file", "path", config.ZoneFilePath)
		return err
	}
	zone, err := parser.DecodeZone(file)
	if err != nil {
		log.Error("Was not able to parse zone file.", "error", err)
		return err
	}
	//TODO CFE be able to add multiple signature to a section
	addSignatureMetaData(zone, keyPhase)
	if rainspub.ConsistencyCheck(zone) {
		return errors.New("Inconsistent section")
	}
	//TODO CFE do this in a go routine
	if err = rainspub.SignSectionUnsafe(zone, keyPhaseToPath); err != nil {
		return err
	}
	//TODO CFE: query new delegation from superordinate server and push them to all rains servers
	msg, err := rainspub.CreateRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
		return err
	}
	connErrors := rainspub.PublishSections(msg, config.ServerAddresses)
	for _, connErr := range connErrors {
		log.Warn("Was not able to send signed zone to this server.", "server", connErr.TCPAddr.String())
		//TODO CFE: Implement error handling
	}
	return nil
}

//TODO CFE change it such that it can be used as envisioned in the
//design-scalable-signature-updates.md
//especially that not all assertions are expiring at the same time
func addSignatureMetaData(zone *rainslib.ZoneSection, keyPhase int) {
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: rainslib.Ed25519,
			KeySpace:  rainslib.RainsKeySpace,
			KeyPhase:  keyPhase,
		},
		ValidSince: time.Now().Add(config.ZoneValidSince).Unix(),
		ValidUntil: time.Now().Add(config.ZoneValidUntil).Unix(),
	}
	zone.AddSig(signature)
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection:
			if sec.Content[0].Type == rainslib.OTDelegation {
				signature.ValidSince = time.Now().Add(config.DelegationValidSince).Unix()
				signature.ValidUntil = time.Now().Add(config.DelegationValidUntil).Unix()
			} else {
				signature.ValidSince = time.Now().Add(config.AssertionValidSince).Unix()
				signature.ValidUntil = time.Now().Add(config.AssertionValidUntil).Unix()
			}
		case *rainslib.ShardSection:
			signature.ValidSince = time.Now().Add(config.ShardValidSince).Unix()
			signature.ValidUntil = time.Now().Add(config.ShardValidUntil).Unix()
		default:
			log.Error("Invalid zone content")
		}
		sec.AddSig(signature)
	}
}
*/
type addressesFlag []rainslib.ConnInfo

func (i *addressesFlag) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *addressesFlag) Set(value string) error {
	var addresses []string
	addresses = strings.Split(value, ",")
	for _, addr := range addresses {
		if tcpAddr, err := net.ResolveTCPAddr("tcp", addr); err == nil {
			*i = append(*i, rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr})
		} else {
			return err
		}
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

func isTrue(v string) bool {
	return v == "true" || v == "ok" || v == "1" || v == "yes" || v == "t"
}

func isFalse(v string) bool {
	return v == "false" || v == "not" || v == "0" || v == "no" || v == "f"
}
