package zonepub

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/rainspub"
	"github.com/netsec-ethz/rains/utils/protoParser"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
)

var msgFramer rainslib.MsgFramer

//Init initializes rainspub
func Init(configPath string) error {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, h))
	err := loadConfig(configPath)
	if err != nil {
		return err
	}
	parser = zoneFileParser.Parser{}
	msgParser = new(protoParser.ProtoParserAndFramer)
	for i, path := range config.ZonePrivateKeyPath {
		keyPhaseToPath[i] = path
	}
	return nil
}

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
	msgParser = new(protoParser.ProtoParserAndFramer)
	return nil
}

//PublishInformation performs periodically the following steps:
//1) Loads the rains zone file.
//2) Adds Signature MetaData
//3) Let rainspub sign the zone
//4) Query the superordinate zone for the new delegation and push it to all rains servers
//5) After rainspub signed the zone, send the signed zone to all rains servers specified in the config
func PublishInformation() {
	timer := make(chan bool)
	result := make(chan bool)
	keyPhase := 0
	//TODO CFE how to handle delegation schedule guarantees for subordinates?
	go waitSeconds(config.PublishInterval, timer)
	go publishZone(result, keyPhase)
	for true {
		select {
		case <-timer:
			go waitSeconds(config.PublishInterval, timer)
			go publishZone(result, keyPhase)
		case success := <-result:
			if !success {
				//TODO CFE handle error
			}
			keyPhase = (keyPhase + 1) % config.NofKeyPhases
		}
	}
}

//waitSeconds waits interval * seconds before it writes to timer
func waitSeconds(interval time.Duration, timer chan<- bool) {
	time.Sleep(interval * time.Second)
	timer <- true
}

//publishZone performs the following steps:
//1) Loads the rains zone file.
//2) Adds Signature MetaData and perform consistency checks on the zone and its signatures
//3) Let rainspub sign the zone
//4) Query the superordinate zone for the new delegation and push it to all rains servers
//5) After rainspub signed the zone, send the signed zone to all rains servers specified in the
//config
//6) write true to success if everything went as expected
func publishZone(success chan<- bool, keyPhase int) error {
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
	if err = checkZone(zone); err != nil {
		return err
	}
	//TODO CFE do this in a go routine
	if err = rainspub.SignSectionUnsafe(zone, keyPhaseToPath); err != nil {
		return err
	}
	//TODO CFE: query new delegation from superordinate server and push them to all rains servers
	msg, err := createRainsMessage(zone)
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

func checkZone(zone *rainslib.ZoneSection) error {
	if !rainsSiglib.ValidSectionAndSignature(zone) {
		return errors.New("zone or zone's signature is not valid")
	}
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection:
			if !rainsSiglib.ValidSectionAndSignature(sec) {
				return errors.New("zone's content or its signature is not valid")
			}
		default:
			return errors.New("Invalid zone content")
		}
	}
	return nil
}

//createRainsMessage creates a rainsMessage containing the given zone and return the byte representation of this rainsMessage ready to send out.
func createRainsMessage(zone *rainslib.ZoneSection) ([]byte, error) {
	msg := rainslib.RainsMessage{Token: rainslib.GenerateToken(), Content: []rainslib.MessageSection{zone}} //no capabilities
	byteMsg, err := msgParser.Encode(msg)
	if err != nil {
		return []byte{}, err
	}
	return byteMsg, nil
}
