package publisher

import (
	"errors"
	"io/ioutil"
	"sort"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/encoder"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
)

//Rainspub represents the publishing process of a zone authority. It can be configured to do
//anything from just one step to the whole process of publishing information to the zone's
//authoritative servers.
type Rainspub struct {
	Config     Config
	zfParser   zonefile.ZoneFileParser
	sigEncoder encoder.SignatureFormatEncoder
}

//New creates a Rainspub instance and returns a pointer to it.
func New(config Config) *Rainspub {
	return &Rainspub{
		Config:     config,
		zfParser:   zonefile.Parser{},
		sigEncoder: zonefile.Parser{},
	}
}

//Publish performs various tasks of a zone's publishing process to rains servers according to its
//configuration. This implementation assumes that there is exactly one zone per zonefile.
func (r *Rainspub) Publish() {
	zone, err := loadZonefile(r.Config.ZonefilePath, r.zfParser)
	if err != nil {
		return
	}
	log.Info("Zonefile successful loaded")
	assertions, shards, pshards, err := splitZoneContent(zone,
		r.Config.ShardingConf.KeepExistingShards, r.Config.PShardingConf.KeepExistingPshards)
	nofAssertions := len(assertions)
	if err != nil {
		return
	}
	if r.Config.ShardingConf.DoSharding {
		if shards, err = doSharding(zone, assertions, shards, r.Config.ShardingConf, r.zfParser,
			r.Config.ConsistencyConf.SortShards); err != nil {
			log.Error(err.Error())
			return
		}
		if !r.Config.PShardingConf.DoPsharding {
			assertions = nil
		}
	}
	if r.Config.PShardingConf.DoPsharding {
		if pshards, err = doPsharding(zone, assertions, pshards, r.Config.PShardingConf); err != nil {
			log.Error(err.Error())
			return
		}
		if r.Config.ShardingConf.DoSharding {
			assertions = nil
		}
	}
	if r.Config.ShardingConf.DoSharding || r.Config.PShardingConf.DoPsharding {
		createZone(zone, assertions, shards, pshards)
	}
	if r.Config.MetaDataConf.AddSignatureMetaData {
		if err = addSignatureMetaData(zone, nofAssertions, len(pshards), r.Config.MetaDataConf); err != nil {
			log.Error(err.Error())
			return
		}
		log.Info("Adding Signature meta data completed successfully")
	}
	if !isConsistent(zone, r.Config.ConsistencyConf) {
		return
	}
	if r.Config.DoSigning {
		if signZone(zone, r.Config.PrivateKeyPath, r.sigEncoder) != nil {
			log.Error("Was not able to sign zone.")
			return
		}
		log.Info("Signing completed successfully")
	}
	r.publishZone(zone, r.Config)
}

//splitZoneContent returns assertions, pshards and shards contained in zone as three separate
//slices.
func splitZoneContent(zone *sections.ZoneSection, keepShards, keepPshards bool) (
	[]*sections.AssertionSection, []*sections.ShardSection, []*sections.PshardSection, error) {
	assertions := []*sections.AssertionSection{}
	shards := []*sections.ShardSection{}
	pshards := []*sections.PshardSection{}
	for _, section := range zone.Content {
		switch s := section.(type) {
		case *sections.AssertionSection:
			assertions = append(assertions, s)
		case *sections.ShardSection:
			if keepShards {
				shards = append(shards, s)
			} else {
				for _, a := range s.Content {
					assertions = append(assertions, a)
				}
			}
		case *sections.PshardSection:
			if keepPshards {
				pshards = append(pshards, s)
			}
		default:
			log.Error("Invalid zone content", "section", s)
			return nil, nil, nil, errors.New("Invalid zone content")
		}
	}
	return assertions, shards, pshards, nil
}

func doSharding(zone *sections.ZoneSection, assertions []*sections.AssertionSection,
	shards []*sections.ShardSection, config ShardingConfig, encoder zonefile.ZoneFileParser,
	sortShards bool) ([]*sections.ShardSection, error) {
	if sortShards {
		sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	}
	var newShards []*sections.ShardSection
	var err error
	if config.MaxShardSize > 0 {
		newShards, err = groupAssertionsToShardsBySize(zone.SubjectZone, zone.Context, assertions,
			config, encoder)
		if err != nil {
			return nil, err
		}
	} else if config.NofAssertionsPerShard > 0 {
		newShards = groupAssertionsToShardsByNumber(zone.SubjectZone, zone.Context, assertions, config)
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

func doPsharding(zone *sections.ZoneSection, assertions []*sections.AssertionSection,
	pshards []*sections.PshardSection, conf PShardingConfig) ([]*sections.PshardSection, error) {
	var newPshards []*sections.PshardSection
	var err error
	if conf.NofAssertionsPerPshard > 0 {
		if newPshards, err = groupAssertionsToPshards(zone.SubjectZone, zone.Context, assertions, conf); err != nil {
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
func groupAssertionsToShardsBySize(subjectZone, context string, assertions []*sections.AssertionSection,
	config ShardingConfig, encoder zonefile.ZoneFileParser) ([]*sections.ShardSection, error) {
	shards := []*sections.ShardSection{}
	sameNameAssertions := groupAssertionByName(assertions, config)
	prevShardAssertionSubjectName := ""
	shard := &sections.ShardSection{}
	for i, sameNameA := range sameNameAssertions {
		shard.Content = append(shard.Content, sameNameA...)
		//FIXME CFE replace with cbor parser
		if length := len(encoder.Encode(shard)); length > config.MaxShardSize {
			shard.Content = shard.Content[:len(shard.Content)-len(sameNameA)]
			if len(shard.Content) == 0 {
				log.Error("Assertions with the same name are larger than maxShardSize",
					"assertions", sameNameA, "length", length, "maxShardSize", config.MaxShardSize)
				return nil, errors.New("Assertions with the same name are too long")
			}
			shard.RangeFrom = prevShardAssertionSubjectName
			shard.RangeTo = sameNameA[0].SubjectName
			shards = append(shards, shard)
			shard = &sections.ShardSection{}
			prevShardAssertionSubjectName = sameNameAssertions[i-1][0].SubjectName
			shard.Content = append(shard.Content, sameNameA...)
			if length := len(encoder.Encode(shard)); length > config.MaxShardSize {
				log.Error("Assertions with the same name are larger than maxShardSize",
					"assertions", sameNameA, "length", length, "maxShardSize", config.MaxShardSize)
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
func groupAssertionByName(assertions []*sections.AssertionSection,
	config ShardingConfig) [][]*sections.AssertionSection {
	var output [][]*sections.AssertionSection
	for i := 0; i < len(assertions); i++ {
		sameName := []*sections.AssertionSection{assertions[i]}
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
	assertions []*sections.AssertionSection, config ShardingConfig) []*sections.ShardSection {
	shards := []*sections.ShardSection{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	shard := &sections.ShardSection{}
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
			shard = &sections.ShardSection{}
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
func groupAssertionsToPshards(subjectZone, context string, assertions []*sections.AssertionSection,
	config PShardingConfig) ([]*sections.PshardSection, error) {
	pshards := []*sections.PshardSection{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	pshard := &sections.PshardSection{}
	bloomFilter := newBloomFilter(config.BloomFilterConf)
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
			pshard = &sections.PshardSection{}
			bloomFilter = newBloomFilter(config.BloomFilterConf)
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

//newBloomFilter returns a newly created bloom filter of the given
func newBloomFilter(config BloomFilterConfig) sections.BloomFilter {
	var size int
	if config.BloomFilterSize%8 == 0 {
		size = config.BloomFilterSize / 8
	} else {
		size = (config.BloomFilterSize/8 + 1) * 8
	}
	return sections.BloomFilter{
		HashFamily:       config.Hashfamily,
		NofHashFunctions: config.NofHashFunctions,
		ModeOfOperation:  config.BFOpMode,
		Filter:           make(bitarray.BitArray, size),
	}
}

//createZone overwrites zone with assertions, pshards and shards in the correct order.
func createZone(zone *sections.ZoneSection, assertions []*sections.AssertionSection,
	shards []*sections.ShardSection, pshards []*sections.PshardSection) {
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
func addSignatureMetaData(zone *sections.ZoneSection, nofAssertions, nofPshards int,
	config MetaDataConfig) error {
	waitInterval := config.SigSigningInterval.Nanoseconds() / int64(nofAssertions)
	pshardWaitInterval := config.SigSigningInterval.Nanoseconds() / int64(nofPshards)
	signature := signature.Signature{
		PublicKeyID: keys.PublicKeyID{
			Algorithm: config.SignatureAlgorithm,
			KeyPhase:  config.KeyPhase,
			KeySpace:  keys.RainsKeySpace,
		},
		ValidSince: int64(config.SigValidSince.Seconds()),
		ValidUntil: int64(config.SigValidUntil.Seconds()),
	}
	firstShard := true
	for _, section := range zone.Content {
		switch s := section.(type) {
		case *sections.AssertionSection:
			return errors.New("standalone assertions in a zone are not supported")
		case *sections.ShardSection:
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
		case *sections.PshardSection:
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

func isConsistent(zone *sections.ZoneSection, config ConsistencyConfig) bool {
	if config.DoConsistencyCheck {
		if !siglib.ValidSectionAndSignature(zone) {
			log.Error("zone content is not consistent")
			return false
		}
	} else {
		if config.SortShards {
			zone.Sort()
		}
		if config.CheckStringFields {
			if !siglib.CheckStringFields(zone) {
				log.Error("zone content is not consistent")
				return false
			}
		}
		if config.SigNotExpired {
			if !siglib.CheckSignatureNotExpired(zone) {
				log.Error("zone content is not consistent")
				return false
			}
		}
	}
	return true
}

func (r *Rainspub) publishZone(zone *sections.ZoneSection, config Config) {
	if config.OutputPath != "" {
		encoding := r.zfParser.Encode(zone)
		err := ioutil.WriteFile(config.OutputPath, []byte(encoding), 0600)
		if err != nil {
			log.Error(err.Error())
		} else {
			log.Info("Writing updated zonefile to disk completed successfully")
		}
	}
	if config.DoPublish {
		//TODO check if zone is not too large. If it is, split it up and send content separately.
		msg := message.RainsMessage{
			Token:   token.GenerateToken(),
			Content: []sections.MessageSection{zone},
			//TODO CFE maybe add capabilities
		}
		unreachableServers := publishSections(msg, config.AuthServers)
		if unreachableServers != nil {
			log.Warn("Was not able to connect to all authoritative servers", "unreachableServers", unreachableServers)
		} else {
			log.Info("publishing to server completed successfully")
		}
	}
}

//publishSections establishes connections to all authoritative servers according to the r.Config. It
//then sends sections to all of them. It returns the connection information of those servers it was
//not able to push sections, otherwise nil is returned.
func publishSections(msg message.RainsMessage, authServers []connection.ConnInfo) []connection.ConnInfo {
	var errorConns []connection.ConnInfo
	results := make(chan *connection.ConnInfo, len(authServers))
	for _, conn := range authServers {
		go connectAndSendMsg(msg, conn, results)
	}
	for i := 0; i < len(authServers); i++ {
		if errorConn := <-results; errorConn != nil {
			errorConns = append(errorConns, *errorConn)
		}
	}
	return errorConns
}
