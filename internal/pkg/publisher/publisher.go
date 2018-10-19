package publisher

import (
	"errors"
	"sort"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

//Rainspub represents the publishing process of a zone authority. It can be configured to do
//anything from just one step to the whole process of publishing information to the zone's
//authoritative servers.
type Rainspub struct {
	Config Config
}

//New creates a Rainspub instance and returns a pointer to it.
func New(config Config) *Rainspub {
	return &Rainspub{
		Config: config,
	}
}

//Publish performs various tasks of a zone's publishing process to rains servers according to its
//configuration. This implementation assumes that there is exactly one zone per zonefile.
func (r *Rainspub) Publish() {
	encoder := zonefile.Parser{}
	zone, err := encoder.LoadZone(r.Config.ZonefilePath)
	if err != nil {
		log.Error(err.Error())
		return
	}
	log.Info("Zonefile successful loaded")
	assertions, shards, pshards, nofAssertions, err := splitZoneContent(zone,
		r.Config.ShardingConf.KeepExistingShards, r.Config.PShardingConf.KeepExistingPshards)
	if err != nil {
		return
	}
	if r.Config.ShardingConf.DoSharding {
		if shards, err = DoSharding(zone.Context, zone.SubjectZone, assertions, shards, r.Config.ShardingConf,
			r.Config.ConsistencyConf.SortShards); err != nil {
			log.Error(err.Error())
			return
		}
		if !r.Config.PShardingConf.DoPsharding {
			assertions = nil
		}
	}
	if r.Config.PShardingConf.DoPsharding {
		if pshards, err = DoPsharding(zone.Context, zone.SubjectZone, assertions, pshards, r.Config.PShardingConf,
			!r.Config.ShardingConf.DoSharding && r.Config.ConsistencyConf.SortShards); err != nil {
			log.Error(err.Error())
			return
		}
		if r.Config.ShardingConf.DoSharding {
			assertions = nil
		}
	}
	if r.Config.ShardingConf.DoSharding || r.Config.PShardingConf.DoPsharding {
		CreateZone(zone, assertions, shards, pshards)
	}
	if r.Config.MetaDataConf.AddSignatureMetaData {
		if err = addSignatureMetaData(zone, nofAssertions, len(pshards), r.Config.MetaDataConf); err != nil {
			log.Error(err.Error())
			return
		}
	}
	if !isConsistent(zone, r.Config.ConsistencyConf) {
		return
	}
	if r.Config.DoSigning {
		if signZone(zone, r.Config.PrivateKeyPath) != nil {
			log.Error("Was not able to sign zone.")
			return
		}
		log.Info("Signing completed successfully")
	}
	if r.Config.OutputPath != "" {
		if err := encoder.EncodeAndStore(r.Config.OutputPath, zone); err != nil {
			log.Error(err.Error())
			return
		}
		log.Info("Writing updated zonefile to disk completed successfully")
	}
	r.publishZone(zone, r.Config)
}

//splitZoneContent returns assertions, pshards and shards contained in zone as three separate
//slices.
func splitZoneContent(zone *section.Zone, keepShards, keepPshards bool) (
	[]*section.Assertion, []*section.Shard, []*section.Pshard, int, error) {
	nofAssertions := 0
	assertions := []*section.Assertion{}
	shards := []*section.Shard{}
	pshards := []*section.Pshard{}
	for _, sec := range zone.Content {
		switch s := sec.(type) {
		case *section.Assertion:
			assertions = append(assertions, s)
			nofAssertions++
		case *section.Shard:
			if keepShards {
				shards = append(shards, s)
			} else {
				for _, a := range s.Content {
					assertions = append(assertions, a)
				}
			}
			nofAssertions += len(s.Content)
		case *section.Pshard:
			if keepPshards {
				pshards = append(pshards, s)
			}
		default:
			log.Error("Invalid zone content", "section", s)
			return nil, nil, nil, 0, errors.New("Invalid zone content")
		}
	}
	return assertions, shards, pshards, nofAssertions, nil
}

//DoSharding creates shards based on the zone's content and config.
func DoSharding(ctx, zone string, assertions []*section.Assertion, shards []*section.Shard,
	config ShardingConfig, sortShards bool) ([]*section.Shard, error) {
	if sortShards {
		sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	}
	var newShards []*section.Shard
	var err error
	if config.MaxShardSize > 0 {
		newShards, err = groupAssertionsToShardsBySize(zone, ctx, assertions,
			config)
		if err != nil {
			return nil, err
		}
	} else if config.NofAssertionsPerShard > 0 {
		newShards = groupAssertionsToShardsByNumber(zone, ctx, assertions, config)
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

//DoPsharding creates pshards based on the zone's content and config.
func DoPsharding(ctx, zone string, assertions []*section.Assertion,
	pshards []*section.Pshard, conf PShardingConfig, sortShards bool) ([]*section.Pshard, error) {
	if sortShards {
		sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	}
	var newPshards []*section.Pshard
	var err error
	if conf.NofAssertionsPerPshard > 0 {
		if newPshards, err = groupAssertionsToPshards(zone, ctx, assertions, conf); err != nil {
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
func groupAssertionsToShardsBySize(subjectZone, context string, assertions []*section.Assertion,
	config ShardingConfig) ([]*section.Shard, error) {
	encoder := zonefile.Parser{}
	shards := []*section.Shard{}
	sameNameAssertions := groupAssertionByName(assertions, config)
	prevShardAssertionSubjectName := ""
	shard := &section.Shard{}
	for i, sameNameA := range sameNameAssertions {
		shard.Content = append(shard.Content, sameNameA...)
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
			shard = &section.Shard{}
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
func groupAssertionByName(assertions []*section.Assertion,
	config ShardingConfig) [][]*section.Assertion {
	var output [][]*section.Assertion
	for i := 0; i < len(assertions); i++ {
		sameName := []*section.Assertion{assertions[i]}
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
	assertions []*section.Assertion, config ShardingConfig) []*section.Shard {
	shards := []*section.Shard{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	shard := &section.Shard{}
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
			shard = &section.Shard{}
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
func groupAssertionsToPshards(subjectZone, context string, assertions []*section.Assertion,
	config PShardingConfig) ([]*section.Pshard, error) {
	pshards := []*section.Pshard{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	pshard := &section.Pshard{}
	bloomFilter := newBloomFilter(config.BloomFilterConf)
	for i, a := range assertions {
		if prevAssertionSubjectName != a.SubjectName {
			nameCount++
			prevAssertionSubjectName = a.SubjectName
		}
		if nameCount > config.NofAssertionsPerPshard {
			pshard.RangeFrom = prevShardAssertionSubjectName
			pshard.RangeTo = a.SubjectName
			pshard.Datastructure.Type = section.BloomFilterType
			pshard.Datastructure.Data = bloomFilter
			pshards = append(pshards, pshard)
			nameCount = 1
			pshard = &section.Pshard{}
			bloomFilter = newBloomFilter(config.BloomFilterConf)
			prevShardAssertionSubjectName = assertions[i-1].SubjectName
		}
		if err := bloomFilter.AddAssertion(a); err != nil {
			return nil, err
		}
	}
	pshard.RangeFrom = prevShardAssertionSubjectName
	pshard.RangeTo = ""
	pshard.Datastructure.Type = section.BloomFilterType
	pshard.Datastructure.Data = bloomFilter
	pshards = append(pshards, pshard)
	log.Info("Sharding by number completed successfully")
	return pshards, nil
}

//newBloomFilter returns a newly created bloom filter of the given
func newBloomFilter(config BloomFilterConfig) section.BloomFilter {
	var size int
	if config.BloomFilterSize%8 == 0 {
		size = config.BloomFilterSize / 8
	} else {
		size = (config.BloomFilterSize/8 + 1) * 8
	}
	return section.BloomFilter{
		HashFamily:       config.Hashfamily,
		NofHashFunctions: config.NofHashFunctions,
		ModeOfOperation:  config.BFOpMode,
		Filter:           make(bitarray.BitArray, size),
	}
}

//CreateZone overwrites zone with assertions, pshards and shards in the correct order.
func CreateZone(zone *section.Zone, assertions []*section.Assertion,
	shards []*section.Shard, pshards []*section.Pshard) {
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
func addSignatureMetaData(zone *section.Zone, nofAssertions, nofPshards int,
	config MetaDataConfig) error {
	signature := signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			Algorithm: config.SignatureAlgorithm,
			KeyPhase:  config.KeyPhase,
			KeySpace:  keys.RainsKeySpace,
		},
		ValidSince: config.SigValidSince,
		ValidUntil: config.SigValidUntil,
	}
	zone.AddSig(signature)
	firstShard := true
	for _, sec := range zone.Content {
		switch s := sec.(type) {
		case *section.Assertion:
			sec.AddSig(signature)
		case *section.Shard:
			waitInterval := config.SigSigningInterval.Nanoseconds() / int64(nofAssertions)
			if firstShard {
				signature.ValidSince = config.SigValidSince
				signature.ValidUntil = config.SigValidUntil
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
		case *section.Pshard:
			if config.AddSigMetaDataToPshards {
				pshardWaitInterval := config.SigSigningInterval.Nanoseconds() / int64(nofPshards)
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

//isConsistent performs the checks specified in config
func isConsistent(zone *section.Zone, config ConsistencyConfig) bool {
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

//publishZone publishes the zone's content either to the specified authoritative servers or to a
//file in zonefile format.
func (r *Rainspub) publishZone(zone *section.Zone, config Config) {
	if config.DoPublish {
		//TODO check if zone is not too large. If it is, split it up and send
		//content separately.
		log.Debug("published zone", "zone", zone)
		msg := message.Message{
			Token:        token.New(),
			Content:      []section.Section{zone},
			Capabilities: []message.Capability{message.NoCapability},
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
func publishSections(msg message.Message, authServers []connection.Info) []connection.Info {
	var errorConns []connection.Info
	results := make(chan *connection.Info, len(authServers))
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
