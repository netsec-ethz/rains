package rainspub

import (
	"crypto/tls"
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
	//TODO CFE uncomment loadConfig() after we have valid information in the config file
	//loadConfig()
	loadKeyPair()
	parser = zoneFileParser.Parser{}
	msgParser = rainsMsgParser.RainsMsgParser{}
}

//PublishInformation sends a signed zone to a rains servers according the the rainspub config
func PublishInformation() {
	//TODO make validSince a parameter. Right now we use current time: time.Now()
	file, err := ioutil.ReadFile(config.zoneFilePath)
	if err != nil {
		log.Error("Was not able to read from zone file.", "path", config.zoneFilePath, "error", err)
	}
	assertions, err := parser.ParseZoneFile(file)
	context := assertions[0].Context
	subjectZone := assertions[1].SubjectZone
	if err != nil {
		log.Error("Zone file malformed.", "error", err)
	}
	signedAssertions := signAssertions(assertions)
	shards := groupAssertionsToShards(context, subjectZone, signedAssertions)
	signedShards := signShards(shards)
	zone := &rainslib.ZoneSection{
		Context:     context,
		SubjectZone: subjectZone,
		Content:     signedShards,
	}
	signZone(zone)
	if err != nil {
		log.Warn("Was not able to sign zone.", "error", err)
	}
	msg, err := createRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
	}
	sendMsg(msg)
}

//signAssertions signs all assertions with the context/zone's private key.
func signAssertions(assertions []*rainslib.AssertionSection) []*rainslib.AssertionSection {
	//TODO CFE use airgapping
	sections := []*rainslib.AssertionSection{}
	for _, a := range assertions {
		stub := a.CreateStub()
		byteStub, err := msgParser.RevParseSignedMsgSection(stub)
		if err == nil {
			sigData := rainslib.SignData(rainslib.Ed25519, privateKey, []byte(byteStub))
			//TODO CFE handle multiple types per assertion
			validUntil := int64(0)
			if a.Content[0].Type == rainslib.OTDelegation {
				validUntil = time.Now().Add(config.delegationValidity).Unix()
			} else {
				validUntil = time.Now().Add(config.assertionValidity).Unix()
			}
			signature := rainslib.Signature{
				Algorithm:  rainslib.Ed25519,
				KeySpace:   rainslib.RainsKeySpace,
				Data:       sigData,
				ValidSince: time.Now().Unix(),
				ValidUntil: validUntil}
			a.Signatures = append(a.Signatures, signature)
			//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
			sections = append(sections, a)
		}
	}
	return sections
}

//groupAssertionsToShards creates shards containing a fixed number of assertions according to the configuration (except the last one).
func groupAssertionsToShards(context, zone string, assertions []*rainslib.AssertionSection) []*rainslib.ShardSection {
	shards := []*rainslib.ShardSection{}
	if len(assertions) <= int(config.maxAssertionsPerShard) {
		return []*rainslib.ShardSection{&rainslib.ShardSection{
			Context:     context,
			SubjectZone: zone,
			RangeFrom:   "",
			RangeTo:     "",
			Content:     assertions,
		}}
	}
	firstShard := &rainslib.ShardSection{
		Context:     context,
		SubjectZone: zone,
		RangeFrom:   "",
		RangeTo:     assertions[config.maxAssertionsPerShard].SubjectName,
		Content:     assertions[:config.maxAssertionsPerShard],
	}
	shards = append(shards, firstShard)
	previousRangeEnd := assertions[config.maxAssertionsPerShard-1].SubjectName
	assertions = assertions[config.maxAssertionsPerShard:]
	for len(assertions) > int(config.maxAssertionsPerShard) {
		shard := &rainslib.ShardSection{
			Context:     context,
			SubjectZone: zone,
			RangeFrom:   previousRangeEnd,
			RangeTo:     assertions[config.maxAssertionsPerShard].SubjectName,
			Content:     assertions[:config.maxAssertionsPerShard],
		}
		shards = append(shards, shard)
		previousRangeEnd = assertions[config.maxAssertionsPerShard-1].SubjectName
		assertions = assertions[config.maxAssertionsPerShard:]
	}
	lastShard := &rainslib.ShardSection{
		Context:     context,
		SubjectZone: zone,
		RangeFrom:   previousRangeEnd,
		RangeTo:     "",
		Content:     assertions,
	}
	shards = append(shards, lastShard)
	return shards
}

//signShards signs all shards with the context/zone's private key.
//Returns signed shards as MessageSectionWithSig
func signShards(shards []*rainslib.ShardSection) []rainslib.MessageSectionWithSig {
	//TODO CFE use airgapping
	sections := []rainslib.MessageSectionWithSig{}
	for _, s := range shards {
		stub := s.CreateStub()
		byteStub, err := msgParser.RevParseSignedMsgSection(stub)
		if err == nil {
			sigData := rainslib.SignData(rainslib.Ed25519, privateKey, []byte(byteStub))
			signature := rainslib.Signature{
				Algorithm:  rainslib.Ed25519,
				KeySpace:   rainslib.RainsKeySpace,
				Data:       sigData,
				ValidSince: time.Now().Unix(),
				ValidUntil: time.Now().Add(config.shardValidity).Unix()}
			s.Signatures = append(s.Signatures, signature)
			//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
			sections = append(sections, s)
		}
	}
	return sections
}

//signZone signs the zone with the context/zone's private key.
func signZone(zone *rainslib.ZoneSection) error {
	//TODO CFE use airgapping
	stub := zone.CreateStub()
	byteStub, err := msgParser.RevParseSignedMsgSection(stub)
	if err != nil {
		return err
	}
	sigData := rainslib.SignData(rainslib.Ed25519, privateKey, []byte(byteStub))
	signature := rainslib.Signature{
		Algorithm:  rainslib.Ed25519,
		KeySpace:   rainslib.RainsKeySpace,
		Data:       sigData,
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(config.zoneValidity).Unix(),
	}
	zone.Signatures = append(zone.Signatures, signature)
	//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
	return nil
}

//sendMsg sends the given zone to rains servers specified in the configuration
func sendMsg(msg []byte) {
	//TODO CFE use certificate for tls
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	for _, server := range config.serverAddresses {
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
