package rainspub

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"rains/rainsSiglib"
	"rains/rainslib"
	"rains/utils/protoParser"
	"rains/utils/zoneFileParser"
	"sort"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//InitRainspub initializes rainspub
func InitRainspub(configPath string) {
	loadConfig(configPath)
	loadPrivateKey(config.ZonePrivateKeyPath)
	parser = zoneFileParser.Parser{}
	msgParser = new(protoParser.ProtoParserAndFramer)
}

//PublishInformation
//1) loads all assertions from the rains zone file.
//2) groups assertions into shards
//3) signs the zone and all contained shards and assertions
//4) create a message containing the zone
//5) send the message to all rains servers specified in the config
func PublishInformation() error {
	assertions, err := loadAssertions()
	if err != nil {
		return err
	}

	//TODO CFE add additional sharding parameters to config/allow for different sharding strategies
	zone := groupAssertionsToShards(assertions)

	//TODO implement signing with airgapping
	signZone(zone, zonePrivateKey)
	if err != nil {
		log.Warn("Was not able to sign zone.", "error", err)
		return err
	}

	//send signed zone to rains servers
	msg, err := createRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
		return err
	}
	sendMsg(msg)
	return nil
}

//loadAssertions returns all assertions contained in the rains zone file or an error.
func loadAssertions() ([]*rainslib.AssertionSection, error) {
	file, err := ioutil.ReadFile(config.ZoneFilePath)
	if err != nil {
		log.Error("Was not able to read zone file", "path", config.ZoneFilePath)
		return nil, err
	}
	assertions, err := parser.Decode(file, config.ZoneFilePath)
	if err != nil {
		log.Error("Was not able to parse zone file.", "error", err)
		return nil, err
	}
	return assertions, nil
}

//groupAssertionsToShards creates shards containing a fixed number of assertions according to the configuration (except the last one).
//Before grouping the assertions, it sorts them.
//It returns a zone section containing the created shards. The contained shards and assertions still have non empty subjectZone and context values
//as these values are needed to generate a signatures
func groupAssertionsToShards(assertions []*rainslib.AssertionSection) *rainslib.ZoneSection {
	context := assertions[0].Context
	zone := assertions[0].SubjectZone
	//the assertion compareTo function sorts first by subjectName. Thus we can use it here.
	sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	shards := []rainslib.MessageSectionWithSigForward{}
	if len(assertions) <= int(config.MaxAssertionsPerShard) {
		shards = []rainslib.MessageSectionWithSigForward{&rainslib.ShardSection{
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
//TODO CFE we should use 2 valid signatures to avoid traffic bursts when a signature expires.
//TODO CFE also support different signature methods
func signZone(zone *rainslib.ZoneSection, privateKey ed25519.PrivateKey) error {
	signature := rainslib.Signature{
		Algorithm: rainslib.Ed25519,
		KeySpace:  rainslib.RainsKeySpace,
		//TODO What time should we choose for valid since?
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(config.ZoneValidity).Unix(),
	}
	if ok := rainsSiglib.SignSection(zone, privateKey, signature, zoneFileParser.Parser{}); !ok {
		return errors.New("Was not able to sign and add the signature")
	}
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.ShardSection:
			err := signShard(sec, privateKey)
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
func signShard(s *rainslib.ShardSection, privateKey ed25519.PrivateKey) error {
	signature := rainslib.Signature{
		Algorithm: rainslib.Ed25519,
		KeySpace:  rainslib.RainsKeySpace,
		//TODO What time should we choose for valid since?
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(config.ShardValidity).Unix()}
	if ok := rainsSiglib.SignSection(s, privateKey, signature, zoneFileParser.Parser{}); !ok {
		return errors.New("Was not able to sign and add the signature")
	}
	//only remove context and subjectZone after signature was added
	s.Context = ""
	s.SubjectZone = ""
	err := signAssertions(s.Content, privateKey)
	return err
}

//signAssertions signs all assertions with the context/zone's private key.
//TODO we should use 2 valid signatures to avoid traffic bursts when a signature expires.
//TODO make validSince a parameter. Right now we use current time: time.Now()
func signAssertions(assertions []*rainslib.AssertionSection, privateKey ed25519.PrivateKey) error {
	for _, a := range assertions {
		//TODO CFE handle multiple types per assertion
		signature := rainslib.Signature{
			Algorithm: rainslib.Ed25519,
			KeySpace:  rainslib.RainsKeySpace,
			//TODO What time should we choose for valid since?
			ValidSince: time.Now().Unix(),
		}
		if a.Content[0].Type == rainslib.OTDelegation {
			signature.ValidUntil = time.Now().Add(config.DelegationValidity).Unix()
		} else {
			signature.ValidUntil = time.Now().Add(config.AssertionValidity).Unix()
		}

		if ok := rainsSiglib.SignSection(a, privateKey, signature, zoneFileParser.Parser{}); !ok {
			return errors.New("Was not able to sign and add the signature")
		}
		a.Context = ""
		a.SubjectZone = ""
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
		case rainslib.TCP:
			conn, err := tls.Dial(server.TCPAddr.Network(), server.String(), conf)
			if err != nil {
				log.Error("Was not able to establish a connection.", "server", server, "error", err)
				continue
			}
			var msgFramer rainslib.MsgFramer
			msgFramer = new(protoParser.ProtoParserAndFramer)
			msgFramer.InitStreams(nil, conn)
			msgFramer.Frame(msg)
			//conn.Close() When should I close this connection? If I do it here, then the destination cannot read the content because it gets an EOF
			log.Info("Message sent", "destination", server.String())
		default:
			log.Warn("Connection Information type does not exist", "ConnInfo type", server.Type)
		}
	}
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
