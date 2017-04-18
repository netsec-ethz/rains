package rainspub

import (
	"crypto/tls"
	"io/ioutil"
	"rains/rainsd"
	"rains/rainslib"
	rainsMsgParser "rains/utils/parser"

	log "github.com/inconshreveable/log15"
)

//InitRainspub initializes rainspub
func InitRainspub() {
	//loadConfig()

	parser = zoneFileParserImpl{}
	msgParser = rainsMsgParser.RainsMsgParser{}
}

//PublishInformation sends a signed zone to a rains servers according the the rainspub config
func PublishInformation() {
	file, err := ioutil.ReadFile(config.zoneFilePath)
	if err != nil {
		log.Error("Was not able to read from zone file.", "path", config.zoneFilePath, "error", err)
	}
	assertions, err := parser.parseZoneFile(file)
	context := assertions[0].Context
	subjectZone := assertions[1].SubjectZone
	if err != nil {
		log.Error("Zone file malformed.", "error", err)
	}
	signAssertions(assertions)
	shards := groupAssertionsToShards(context, subjectZone, assertions)
	signedShards := signShards(shards)
	zone := &rainslib.ZoneSection{
		Context:     context,
		SubjectZone: subjectZone,
		Content:     signedShards,
	}
	signZone(zone)
	msg, err := createRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
	}
	//TODO CFE sign message?
	sendMsg(msg)
}

//signAssertions signs all assertions with the context/zone's private key.
func signAssertions([]*rainslib.AssertionSection) {
	//TODO CFE use airgapping
	//TODO CFE implement
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
func signShards([]*rainslib.ShardSection) []rainslib.MessageSectionWithSig {
	//TODO CFE use airgapping
	//TODO CFE implement
	return nil
}

//signZone signs the zone with the context/zone's private key.
func signZone(zone *rainslib.ZoneSection) {
	//TODO CFE use airgapping
	//TODO CFE implement
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
	//TODO CFE add signature to the message?
	byteMsg, err := msgParser.ParseRainsMsg(msg)
	if err != nil {
		return []byte{}, err
	}
	return byteMsg, nil
}
