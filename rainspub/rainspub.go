package rainspub

import (
	"errors"
	"io/ioutil"
	"sort"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"
	"github.com/netsec-ethz/rains/utils/yaccZonefileParser"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
)

//Init starts the zone information publishing process according to the provided config.
func Init(inputConfig Config) {
	config = inputConfig
	parser = yaccZonefileParser.Parser{}
	signatureEncoder = zoneFileParser.Parser{}
	publish()
}

//publish calls the relevant library function to publish information according to the provided
//config during initialization.
//this implementation assumes that there is exactly one zone per zonefile.
func publish() {
	zone, err := loadZonefile()
	if err != nil {
		return
	}
	log.Info("Zonefile successful loaded")
	var nofAssertions int
	if config.DoSharding {
		if nofAssertions, err = doSharding(zone); err != nil {
			log.Error(err.Error())
			return
		}
	}
	if config.AddSignatureMetaData {
		if err = addSignatureMetaData(zone, nofAssertions); err != nil {
			log.Error(err.Error())
			return
		}
		log.Info("Adding Signature meta data completed successfully")
	}
	if !isConsistent(zone) {
		return
	}
	if config.DoSigning {
		if signZone(zone) != nil {
			log.Error("Was not able to sign zone.")
			return
		}
		log.Info("Signing completed successfully")
	}
	publishZone(zone)
}

func doSharding(zone *rainslib.ZoneSection) (int, error) {
	assertions, shards, err := splitZoneContent(zone)
	if err != nil {
		return 0, err
	}
	if config.SortShards {
		sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	}
	var newShards []*rainslib.ShardSection
	if config.MaxShardSize > 0 {
		newShards, err = groupAssertionsToShardsBySize(zone.SubjectZone, zone.Context, assertions, config.MaxShardSize)
		if err != nil {
			return 0, err
		}
	} else if config.NofAssertionsPerShard > 0 {
		newShards = groupAssertionsToShardsByNumber(zone.SubjectZone, zone.Context, assertions)
	} else {
		return 0, errors.New("MaxShardSize or NofAssertionsPerShard must be positive when DoSharding is set")
	}
	if len(shards) != 0 {
		shards = append(shards, newShards...)
		sort.Slice(shards, func(i, j int) bool { return shards[i].CompareTo(shards[j]) < 0 })
	} else {
		shards = newShards
	}
	zone.Content = nil
	for _, s := range shards {
		zone.Content = append(zone.Content, s)
	}
	return len(assertions), nil
}

//splitZoneContent returns an array of assertions and an array of shards contained in zone.
func splitZoneContent(zone *rainslib.ZoneSection) ([]*rainslib.AssertionSection,
	[]*rainslib.ShardSection, error) {
	assertions := []*rainslib.AssertionSection{}
	shards := []*rainslib.ShardSection{}
	for _, section := range zone.Content {
		switch s := section.(type) {
		case *rainslib.AssertionSection:
			assertions = append(assertions, s)
		case *rainslib.ShardSection:
			if config.KeepExistingShards {
				shards = append(shards, s)
			} else {
				for _, a := range s.Content {
					assertions = append(assertions, a)
				}
			}
		default:
			log.Error("Invalid zone content", "section", s)
			return nil, nil, errors.New("Invalid zone content")
		}
	}
	return assertions, shards, nil
}

//groupAssertionsToShardsBySize groups assertions into shards such that each shard is not exceeding
//maxSize. It returns a slice of the created shards.
func groupAssertionsToShardsBySize(subjectZone, context string,
	assertions []*rainslib.AssertionSection, maxSize int) ([]*rainslib.ShardSection, error) {
	shards := []*rainslib.ShardSection{}
	sameNameAssertions := groupAssertionByName(assertions)
	prevShardAssertionSubjectName := ""
	shard := &rainslib.ShardSection{}
	for i, sameNameA := range sameNameAssertions {
		shard.Content = append(shard.Content, sameNameA...)
		//FIXME CFE replace with cbor parser
		if length := len(parser.Encode(shard)); length > maxSize {
			shard.Content = shard.Content[:len(shard.Content)-len(sameNameA)]
			if len(shard.Content) == 0 {
				log.Error("Assertions with the same name are larger than maxShardSize",
					"assertions", sameNameA, "length", length, "maxShardSize", maxSize)
				return nil, errors.New("Assertions with the same name are too long")
			}
			shard.RangeFrom = prevShardAssertionSubjectName
			shard.RangeTo = sameNameA[0].SubjectName
			shards = append(shards, shard)
			shard = &rainslib.ShardSection{}
			prevShardAssertionSubjectName = sameNameAssertions[i-1][0].SubjectName
			shard.Content = append(shard.Content, sameNameA...)
			if length := len(parser.Encode(shard)); length > maxSize {
				log.Error("Assertions with the same name are larger than maxShardSize",
					"assertions", sameNameA, "length", length, "maxShardSize", maxSize)
				return nil, errors.New("Assertions with the same name are too long")
			}
		}
	}
	shard.RangeFrom = prevShardAssertionSubjectName
	shard.RangeTo = ""
	shards = append(shards, shard)
	log.Info("Sharding by size completed successfully")
	return shards, nil
}

//groupAssertionByName returns a slice where each entry is a slice of assertions having the same
//subject name.
func groupAssertionByName(assertions []*rainslib.AssertionSection) [][]*rainslib.AssertionSection {
	var output [][]*rainslib.AssertionSection
	for i := 0; i < len(assertions); i++ {
		sameName := []*rainslib.AssertionSection{assertions[i]}
		name := assertions[i].SubjectName
		for i++; i < len(assertions) && assertions[i].SubjectName == name; i++ {
			sameName = append(sameName, assertions[i])
		}
		output = append(output, sameName)
		i--
	}
	return output
}

//groupAssertionsToShardsByNumber creates shards containing a maximum number of different assertion
//names according to the configuration. It returns a slice of the created shards.
func groupAssertionsToShardsByNumber(subjectZone, context string,
	assertions []*rainslib.AssertionSection) []*rainslib.ShardSection {
	shards := []*rainslib.ShardSection{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	shard := &rainslib.ShardSection{}
	for i, a := range assertions {
		if prevAssertionSubjectName != a.SubjectName {
			nameCount++
			prevAssertionSubjectName = a.SubjectName
		}
		if nameCount > config.NofAssertionsPerShard {
			shard.RangeFrom = prevShardAssertionSubjectName
			shard.RangeTo = a.SubjectName
			shards = append(shards, shard)
			nameCount = 1
			shard = &rainslib.ShardSection{}
			prevShardAssertionSubjectName = assertions[i-1].SubjectName
		}
		shard.Content = append(shard.Content, a)
	}
	shard.RangeFrom = prevShardAssertionSubjectName
	shard.RangeTo = ""
	shards = append(shards, shard)
	log.Info("Sharding by number completed successfully")
	return shards
}

func addSignatureMetaData(zone *rainslib.ZoneSection, nofAssertions int) error {
	waitInterval := config.SigSigningInterval.Nanoseconds() / int64(nofAssertions)
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: config.SignatureAlgorithm,
			KeyPhase:  config.KeyPhase,
			KeySpace:  rainslib.RainsKeySpace,
		},
		ValidSince: int64(config.SigValidSince.Seconds()),
		ValidUntil: int64(config.SigValidUntil.Seconds()),
	}
	for _, section := range zone.Content {
		shard, ok := section.(*rainslib.ShardSection)
		if !ok {
			return errors.New("standalone assertions in a zone are not supported")
		}
		if config.AddSigMetaDataToShards {
			shard.AddSig(signature)
		}
		if config.AddSigMetaDataToAssertions {
			for _, assertion := range shard.Content {
				assertion.AddSig(signature)
				signature.ValidSince += waitInterval / int64(time.Second)
				signature.ValidUntil += waitInterval / int64(time.Second)
			}
		} else {
			signature.ValidSince += waitInterval * int64(len(shard.Content)) / int64(time.Second)
			signature.ValidUntil += waitInterval * int64(len(shard.Content)) / int64(time.Second)
		}
	}
	return nil
}

func isConsistent(zone *rainslib.ZoneSection) bool {
	if config.DoConsistencyCheck {
		if !rainsSiglib.ValidSectionAndSignature(zone) {
			log.Error("zone content is not consistent")
			return false
		}
	} else {
		if config.SortShards {
			zone.Sort()
		}
		if config.CheckStringFields {
			if !rainsSiglib.CheckStringFields(zone) {
				log.Error("zone content is not consistent")
				return false
			}
		}
		if config.SigNotExpired {
			if !rainsSiglib.CheckSignatureNotExpired(zone) {
				log.Error("zone content is not consistent")
				return false
			}
		}
	}
	return true
}

func publishZone(zone *rainslib.ZoneSection) {
	if config.OutputPath != "" {
		encoding := parser.Encode(zone)
		err := ioutil.WriteFile(config.OutputPath, []byte(encoding), 0600)
		if err != nil {
			log.Error(err.Error())
		} else {
			log.Info("Writing updated zonefile to disk completed successfully")
		}
	}
	if config.DoPublish {
		//TODO check if zone is not too large. If it is, split it up and send content separately.
		encoding, err := createRainsMessage([]rainslib.MessageSectionWithSigForward{zone})
		if err != nil {
			return
		}
		unreachableServers := publishSections(encoding)
		if unreachableServers != nil {
			log.Warn("Was not able to connect to all authoritative servers", "unreachableServers", unreachableServers)
		} else {
			log.Info("publishing to server completed successfully")
		}
	}
}

//createRainsMessage creates a rainsMessage containing the given zone and
//returns the byte representation of this rainsMessage ready to send out.
func createRainsMessage(sections []rainslib.MessageSectionWithSigForward) ([]byte, error) {
	msg := rainslib.RainsMessage{Token: rainslib.GenerateToken()} //no capabilities
	for _, section := range sections {
		msg.Content = append(msg.Content, section)
	}
	//FIXME CFE use CBOR
	msgParser := new(protoParser.ProtoParserAndFramer)
	byteMsg, err := msgParser.Encode(msg)
	if err != nil {
		return []byte{}, err
	}
	return byteMsg, nil
}

//publishSections establishes connections to all authoritative servers according to the config. It
//then sends sections to all of them. It returns the connection information of those servers it was
//not able to push sections, otherwise nil is returned.
func publishSections(sections []byte) []rainslib.ConnInfo {
	var errorConns []rainslib.ConnInfo
	results := make(chan *rainslib.ConnInfo, len(config.AuthServers))
	for _, conn := range config.AuthServers {
		go connectAndSendMsg(sections, conn, results)
	}
	for i := 0; i < len(config.AuthServers); i++ {
		if errorConn := <-results; errorConn != nil {
			errorConns = append(errorConns, *errorConn)
		}
	}
	return errorConns
}
