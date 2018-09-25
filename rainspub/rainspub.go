package rainspub

import (
	"errors"
	"io/ioutil"
	"sort"
	"time"

	"github.com/netsec-ethz/rains/utils/bitarray"
	"github.com/netsec-ethz/rains/utils/protoParser"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
)

//Init starts the zone information publishing process according to the provided config.
func Init(inputConfig Config) {
	config = inputConfig
	zfParser = parser.Parser{}
	signatureEncoder = parser.Parser{}
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
	assertions, shards, pshards, err := splitZoneContent(zone)
	nofAssertions := len(assertions)
	if err != nil {
		return
	}
	if config.DoSharding {
		if shards, err = doSharding(zone, assertions, shards); err != nil {
			log.Error(err.Error())
			return
		}
		if !config.DoPsharding {
			assertions = nil
		}
	}
	if config.DoPsharding {
		if pshards, err = doPsharding(zone, assertions, pshards); err != nil {
			log.Error(err.Error())
			return
		}
		if config.DoSharding {
			assertions = nil
		}
	}
	if config.DoSharding || config.DoPsharding {
		createZone(zone, assertions, shards, pshards)
	}
	if config.AddSignatureMetaData {
		if err = addSignatureMetaData(zone, nofAssertions, len(pshards)); err != nil {
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

//splitZoneContent returns an array of assertions and an array of shards contained in zone.
func splitZoneContent(zone *rainslib.ZoneSection) ([]*rainslib.AssertionSection,
	[]*rainslib.ShardSection, []*rainslib.PshardSection, error) {
	assertions := []*rainslib.AssertionSection{}
	shards := []*rainslib.ShardSection{}
	pshards := []*rainslib.PshardSection{}
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
		case *rainslib.PshardSection:
			if config.KeepExistingPshards {
				pshards = append(pshards, s)
			}
		default:
			log.Error("Invalid zone content", "section", s)
			return nil, nil, nil, errors.New("Invalid zone content")
		}
	}
	return assertions, shards, pshards, nil
}

func doSharding(zone *rainslib.ZoneSection, assertions []*rainslib.AssertionSection,
	shards []*rainslib.ShardSection) ([]*rainslib.ShardSection, error) {
	if config.SortShards {
		sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	}
	var newShards []*rainslib.ShardSection
	var err error
	if config.MaxShardSize > 0 {
		newShards, err = groupAssertionsToShardsBySize(zone.SubjectZone, zone.Context, assertions,
			config.MaxShardSize)
		if err != nil {
			return nil, err
		}
	} else if config.NofAssertionsPerShard > 0 {
		newShards = groupAssertionsToShardsByNumber(zone.SubjectZone, zone.Context, assertions)
	} else {
		return nil, errors.New("MaxShardSize or NofAssertionsPerShard must be positive when DoSharding is set")
	}
	if len(shards) != 0 {
		shards = append(shards, newShards...)
		sort.Slice(shards, func(i, j int) bool { return shards[i].CompareTo(shards[j]) < 0 })
	} else {
		shards = newShards
	}
	return shards, nil
}

func doPsharding(zone *rainslib.ZoneSection, assertions []*rainslib.AssertionSection,
	pshards []*rainslib.PshardSection) ([]*rainslib.PshardSection, error) {
	var newPshards []*rainslib.PshardSection
	var err error
	if config.NofAssertionsPerPshard > 0 {
		if newPshards, err = groupAssertionsToPshards(zone.SubjectZone, zone.Context, assertions); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("NofAssertionsPerPshard must be positive when DoPsharding is set")
	}
	if len(pshards) != 0 {
		pshards = append(pshards, newPshards...)
		sort.Slice(pshards, func(i, j int) bool { return pshards[i].CompareTo(pshards[j]) < 0 })
	} else {
		pshards = newPshards
	}
	return pshards, nil
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
		if length := len(zfParser.Encode(shard)); length > maxSize {
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
			if length := len(zfParser.Encode(shard)); length > maxSize {
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

//groupAssertionsToShardsByNumber creates shards containing a maximum number of different assertion
//names according to the configuration. It returns a slice of the created shards.
func groupAssertionsToPshards(subjectZone, context string,
	assertions []*rainslib.AssertionSection) ([]*rainslib.PshardSection, error) {
	pshards := []*rainslib.PshardSection{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	pshard := &rainslib.PshardSection{}
	bloomFilter := getBloomFilter()
	for i, a := range assertions {
		if prevAssertionSubjectName != a.SubjectName {
			nameCount++
			prevAssertionSubjectName = a.SubjectName
		}
		if nameCount > config.NofAssertionsPerPshard {
			pshard.RangeFrom = prevShardAssertionSubjectName
			pshard.RangeTo = a.SubjectName
			pshard.Datastructure.Data = bloomFilter
			pshards = append(pshards, pshard)
			nameCount = 1
			pshard = &rainslib.PshardSection{}
			bloomFilter = getBloomFilter()
			prevShardAssertionSubjectName = assertions[i-1].SubjectName
		}
		if err := bloomFilter.AddAssertion(a); err != nil {
			return nil, err
		}
	}
	pshard.RangeFrom = prevShardAssertionSubjectName
	pshard.RangeTo = ""
	pshard.Datastructure.Data = bloomFilter
	pshards = append(pshards, pshard)
	log.Info("Sharding by number completed successfully")
	return pshards, nil
}

func getBloomFilter() rainslib.BloomFilter {
	var size int
	if config.BloomFilterSize%8 == 0 {
		size = config.BloomFilterSize / 8
	} else {
		size = (config.BloomFilterSize/8 + 1) * 8
	}
	return rainslib.BloomFilter{
		HashFamily:       config.Hashfamily,
		NofHashFunctions: config.NofHashFunctions,
		ModeOfOperation:  config.BFOpMode,
		Filter:           make(bitarray.BitArray, size),
	}
}

//createZone overwrites zone with assertions, pshards and shards in the correct order.
func createZone(zone *rainslib.ZoneSection, assertions []*rainslib.AssertionSection,
	shards []*rainslib.ShardSection, pshards []*rainslib.PshardSection) {
	zone.Content = nil
	for _, a := range assertions {
		zone.Content = append(zone.Content, a)
	}
	for _, s := range pshards {
		zone.Content = append(zone.Content, s)
	}
	for _, s := range shards {
		zone.Content = append(zone.Content, s)
	}
}

//addSignatureMetaData adds signature meta data to the zone content based on the configuration. It
//assumes, that the zone content is sorted, i.e. pshards come before shards.
func addSignatureMetaData(zone *rainslib.ZoneSection, nofAssertions, nofPshards int) error {
	waitInterval := config.SigSigningInterval.Nanoseconds() / int64(nofAssertions)
	pshardWaitInterval := config.SigSigningInterval.Nanoseconds() / int64(nofPshards)
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: config.SignatureAlgorithm,
			KeyPhase:  config.KeyPhase,
			KeySpace:  rainslib.RainsKeySpace,
		},
		ValidSince: int64(config.SigValidSince.Seconds()),
		ValidUntil: int64(config.SigValidUntil.Seconds()),
	}
	firstShard := true
	for _, section := range zone.Content {
		switch s := section.(type) {
		case *rainslib.AssertionSection:
			return errors.New("standalone assertions in a zone are not supported")
		case *rainslib.ShardSection:
			if firstShard {
				signature.ValidSince = int64(config.SigValidSince.Seconds())
				signature.ValidUntil = int64(config.SigValidUntil.Seconds())
			}
			if config.AddSigMetaDataToShards {
				s.AddSig(signature)
			}
			if config.AddSigMetaDataToAssertions {
				for _, assertion := range s.Content {
					assertion.AddSig(signature)
					signature.ValidSince += waitInterval / int64(time.Second)
					signature.ValidUntil += waitInterval / int64(time.Second)
				}
			} else {
				signature.ValidSince += waitInterval * int64(len(s.Content)) / int64(time.Second)
				signature.ValidUntil += waitInterval * int64(len(s.Content)) / int64(time.Second)
			}
		case *rainslib.PshardSection:
			if config.AddSigMetaDataToPshards {
				s.AddSig(signature)
				signature.ValidSince += pshardWaitInterval / int64(time.Second)
				signature.ValidUntil += pshardWaitInterval / int64(time.Second)
			}
		default:
			return errors.New("unknown section type in zone")
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
		encoding := zfParser.Encode(zone)
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
