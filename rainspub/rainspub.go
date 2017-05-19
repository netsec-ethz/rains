package rainspub

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"rains/rainsd"
	"rains/rainslib"
	rainsMsgParser "rains/utils/parser"
	"rains/utils/zoneFileParser"
	"time"

	log "github.com/inconshreveable/log15"
)

//InitRainspub initializes rainspub
func InitRainspub() {
	loadConfig()
	loadPrivateKey()
	parser = zoneFileParser.Parser{}
	msgParser = rainsMsgParser.RainsMsgParser{}
}

//PublishInformation sends a signed zone to a rains servers according the the rainspub config
func PublishInformation() {
	//TODO make validSince a parameter. Right now we use current time: time.Now()
	assertions, err := loadAssertions()
	if err != nil {
		log.Error("Was not able to load and parse zone file", "error", err)
	}
	//TODO add additional sharding parameters to config/allow for different sharding strategies
	zone := groupAssertionsToShards(assertions)

	//TODO implement signing with airgapping
	signZone(zone)
	if err != nil {
		log.Warn("Was not able to sign zone.", "error", err)
	}

	//send signed zone to rains server
	msg, err := createRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
	}
	sendMsg(msg)
}

func loadAssertions() ([]*rainslib.AssertionSection, error) {
	file, err := ioutil.ReadFile(config.ZoneFilePath)
	if err != nil {
		return []*rainslib.AssertionSection{}, err
	}
	assertions, err := parser.ParseZoneFile(file)
	if err != nil {
		return []*rainslib.AssertionSection{}, err
	}
	return assertions, nil
}

//groupAssertionsToShards creates shards containing a fixed number of assertions according to the configuration (except the last one).
func groupAssertionsToShards(assertions []*rainslib.AssertionSection) *rainslib.ZoneSection {
	context := assertions[0].Context
	zone := assertions[0].SubjectZone
	shards := []rainslib.MessageSectionWithSig{}
	if len(assertions) <= int(config.MaxAssertionsPerShard) {
		shards = []rainslib.MessageSectionWithSig{&rainslib.ShardSection{
			Context:     context,
			SubjectZone: zone,
			RangeFrom:   "",
			RangeTo:     "",
			Content:     assertions,
		}}
	} else {
		firstShard := &rainslib.ShardSection{
			Context:     context,
			SubjectZone: zone,
			RangeFrom:   "",
			RangeTo:     assertions[config.MaxAssertionsPerShard].SubjectName,
			Content:     assertions[:config.MaxAssertionsPerShard],
		}
		shards = append(shards, firstShard)
		previousRangeEnd := assertions[config.MaxAssertionsPerShard-1].SubjectName
		assertions = assertions[config.MaxAssertionsPerShard:]
		for len(assertions) > int(config.MaxAssertionsPerShard) {
			shard := &rainslib.ShardSection{
				Context:     context,
				SubjectZone: zone,
				RangeFrom:   previousRangeEnd,
				RangeTo:     assertions[config.MaxAssertionsPerShard].SubjectName,
				Content:     assertions[:config.MaxAssertionsPerShard],
			}
			shards = append(shards, shard)
			previousRangeEnd = assertions[config.MaxAssertionsPerShard-1].SubjectName
			assertions = assertions[config.MaxAssertionsPerShard:]
		}
		lastShard := &rainslib.ShardSection{
			Context:     context,
			SubjectZone: zone,
			RangeFrom:   previousRangeEnd,
			RangeTo:     "",
			Content:     assertions,
		}
		shards = append(shards, lastShard)
	}
	section := &rainslib.ZoneSection{
		Context:     context,
		SubjectZone: zone,
		Content:     shards,
	}
	return section
}

//signZone signs the zone and all contained shards with the context/zone's private key.
//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
func signZone(zone *rainslib.ZoneSection) error {
	stub := zone.CreateStub()
	byteStub, err := msgParser.RevParseSignedMsgSection(stub)
	if err != nil {
		return err
	}
	sigData := rainslib.SignData(rainslib.Ed25519, privateKey, []byte(byteStub))
	signature := rainslib.Signature{
		Algorithm: rainslib.Ed25519,
		KeySpace:  rainslib.RainsKeySpace,
		Data:      sigData,
		//TODO What time should we choose for valid since?
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(config.ZoneValidity).Unix(),
	}
	zone.Signatures = append(zone.Signatures, signature)

	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.ShardSection:
			err := signShard(sec)
			if err != nil {
				return err
			}
		default:
			log.Warn(fmt.Sprintf("Content of the zone section must be a shard. Got:%T", sec))
		}
	}
	return nil
}

//signShard signs the shard and all contained assertions with the context/zone's private key.
//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
func signShard(s *rainslib.ShardSection) error {
	stub := s.CreateStub()
	byteStub, err := msgParser.RevParseSignedMsgSection(stub)
	if err != nil {
		return err
	}
	sigData := rainslib.SignData(rainslib.Ed25519, privateKey, []byte(byteStub))
	signature := rainslib.Signature{
		Algorithm: rainslib.Ed25519,
		KeySpace:  rainslib.RainsKeySpace,
		Data:      sigData,
		//TODO What time should we choose for valid since?
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(config.ShardValidity).Unix()}
	s.Signatures = append(s.Signatures, signature)
	err = signAssertions(s.Content)
	return err
}

//signAssertions signs all assertions with the context/zone's private key.
//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
func signAssertions(assertions []*rainslib.AssertionSection) error {
	for _, a := range assertions {
		stub := a.CreateStub()
		byteStub, err := msgParser.RevParseSignedMsgSection(stub)
		if err != nil {
			return err
		}
		sigData := rainslib.SignData(rainslib.Ed25519, privateKey, []byte(byteStub))
		//TODO CFE handle multiple types per assertion
		validUntil := int64(0)
		if a.Content[0].Type == rainslib.OTDelegation {
			validUntil = time.Now().Add(config.DelegationValidity).Unix()
		} else {
			validUntil = time.Now().Add(config.AssertionValidity).Unix()
		}
		signature := rainslib.Signature{
			Algorithm: rainslib.Ed25519,
			KeySpace:  rainslib.RainsKeySpace,
			Data:      sigData,
			//TODO What time should we choose for valid since?
			ValidSince: time.Now().Unix(),
			ValidUntil: validUntil}
		a.Signatures = append(a.Signatures, signature)
	}
	return nil
}

//sendMsg sends the given zone to rains servers specified in the configuration
func sendMsg(msg []byte) {
	//TODO CFE use certificate for tls
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	for _, server := range config.ServerAddresses {
		switch server.Type {
		case rainsd.TCP:
			conn, err := tls.Dial("tcp", server.String(), conf)
			if err != nil {
				log.Error("Was not able to establish a connection.", "server", server, "error", err)
				continue
			}
			conn.Write(msg)
			conn.Close()
		default:
			log.Warn("Connection Information type does not exist", "ConnInfo type", server.Type)
		}
	}
}

//createRainsMessage creates a rainsMessage containing the given zone and return the byte representation of this rainsMessage ready to send out.
func createRainsMessage(zone *rainslib.ZoneSection) ([]byte, error) {
	msg := rainslib.RainsMessage{Token: rainslib.GenerateToken(), Content: []rainslib.MessageSection{zone}} //no capabilities
	byteMsg, err := msgParser.ParseRainsMsg(msg)
	if err != nil {
		return []byte{}, err
	}
	return byteMsg, nil
}
