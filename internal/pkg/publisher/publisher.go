package publisher

import (
	"errors"
	"fmt"
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
	encoder := zonefile.IO{}
	zoneContent, err := encoder.LoadZonefile(r.Config.ZonefilePath)
	if err != nil {
		log.Error(err.Error())
		return
	}
	log.Info("Zonefile successful loaded")
	zone, shards, pshards, err := splitZoneContent(zoneContent,
		!r.Config.ShardingConf.IncludeShards, !r.Config.PShardingConf.IncludePshards)
	if err != nil {
		log.Error(err.Error())
		return
	}
	if r.Config.ShardingConf.DoSharding {
		if shards, err = DoSharding(zone.SubjectZone, zone.Context, zone.Content, shards,
			r.Config.ShardingConf, r.Config.ConsistencyConf.SortShards); err != nil {
			log.Error(err.Error())
			return
		}
	}
	//FIXME CFE test if zone.Content is sorted
	if r.Config.PShardingConf.DoPsharding {
		if pshards, err = DoPsharding(zone.SubjectZone, zone.Context, zone.Content, pshards,
			r.Config.PShardingConf,
			!r.Config.ShardingConf.IncludeShards && r.Config.ConsistencyConf.SortShards); err != nil {
			log.Error(err.Error())
			return
		}
	}
	if r.Config.ConsistencyConf.SortZone {
		sort.Slice(zone.Content, func(i, j int) bool { return zone.Content[i].CompareTo(zone.Content[j]) < 0 })
	}
	if r.Config.MetaDataConf.AddSignatureMetaData {
		addSignatureMetaData(zone, shards, pshards, r.Config.MetaDataConf)
	}
	if !isConsistent(zone, shards, pshards, r.Config.ConsistencyConf) {
		return
	}
	if r.Config.DoSigning {
		if err := signZoneContent(zone, shards, pshards, r.Config.PrivateKeyPath); err != nil {
			log.Error(err.Error())
			return
		}
		log.Info("Signing completed successfully")
	}
	output := []section.Section{zone}
	for _, shard := range shards {
		output = append(output, shard)
	}
	for _, pshard := range pshards {
		output = append(output, pshard)
	}
	if r.Config.OutputPath != "" {
		if err := encoder.EncodeAndStore(r.Config.OutputPath, output); err != nil {
			log.Error(err.Error())
			return
		}
		log.Info("Writing updated zonefile to disk completed successfully")
	}
	r.publishZone(output, r.Config)
}

//splitZoneContent returns assertions, pshards and shards contained in zone as three separate
//slices.
func splitZoneContent(zoneContent []section.WithSigForward, keepShards, keepPshards bool) (
	*section.Zone, []*section.Shard, []*section.Pshard, error) {
	shards := []*section.Shard{}
	pshards := []*section.Pshard{}
	var zone *section.Zone
	for _, s := range zoneContent {
		switch s := s.(type) {
		case *section.Shard:
			if keepShards {
				shards = append(shards, s)
			}
		case *section.Pshard:
			if keepPshards {
				pshards = append(pshards, s)
			}
		case *section.Zone:
			zone = s
		default:
			return nil, nil, nil, fmt.Errorf("Unexpected type in zonefile: %T", s)
		}
	}
	if zone == nil {
		return nil, nil, nil, fmt.Errorf("Zone is not in zonefile: %v", zoneContent)
	}
	return zone, shards, pshards, nil
}

//DoSharding creates shards based on the zone's content and config.
func DoSharding(zone, ctx string, assertions []*section.Assertion, shards []*section.Shard,
	config ShardingConfig, sortAssertions bool) ([]*section.Shard, error) {
	if sortAssertions {
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
func DoPsharding(zone, ctx string, assertions []*section.Assertion,
	pshards []*section.Pshard, conf PShardingConfig, sortAssertions bool) ([]*section.Pshard, error) {
	if sortAssertions {
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
	encoder := zonefile.IO{}
	shards := []*section.Shard{}
	sameNameAssertions := groupAssertionByName(assertions, config)
	prevShardAssertionSubjectName := ""
	shard := &section.Shard{}
	for i, sameNameA := range sameNameAssertions {
		shard.Content = append(shard.Content, sameNameA...)
		if length := len(encoder.EncodeSection(shard)); length > config.MaxShardSize {
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
			if length := len(encoder.EncodeSection(shard)); length > config.MaxShardSize {
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
	pshard := newPshard(subjectZone, context, config.BloomFilterConf)
	for i, a := range assertions {
		if prevAssertionSubjectName != a.SubjectName {
			nameCount++
			prevAssertionSubjectName = a.SubjectName
		}
		if nameCount > config.NofAssertionsPerPshard {
			pshard.RangeFrom = prevShardAssertionSubjectName
			pshard.RangeTo = a.SubjectName
			pshards = append(pshards, pshard)
			nameCount = 1
			pshard = newPshard(subjectZone, context, config.BloomFilterConf)
			prevShardAssertionSubjectName = assertions[i-1].SubjectName
		}
		if err := pshard.AddAssertion(a); err != nil {
			return nil, err
		}
	}
	pshard.RangeFrom = prevShardAssertionSubjectName
	pshard.RangeTo = ""
	pshards = append(pshards, pshard)
	log.Info("Psharding by number completed successfully")
	return pshards, nil
}

//newBloomFilter returns a newly created bloom filter of the given
func newPshard(subjectZone, context string, config BloomFilterConfig) *section.Pshard {
	var size int
	if config.BloomFilterSize%8 == 0 {
		size = config.BloomFilterSize / 8
	} else {
		size = (config.BloomFilterSize/8 + 1) * 8
	}
	return &section.Pshard{
		SubjectZone: subjectZone,
		Context:     context,
		BloomFilter: section.BloomFilter{
			Algorithm: config.BFAlgo,
			Hash:      config.BFHash,
			Filter:    make(bitarray.BitArray, size),
		},
	}
}

//addSignatureMetaData adds signature meta data to the section based on the configuration.
func addSignatureMetaData(zone *section.Zone, shards []*section.Shard, pshards []*section.Pshard,
	config MetaDataConfig) {
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
	assertionWaitInterval := config.SigSigningInterval.Nanoseconds() / int64(len(zone.Content))
	shardWaitInterval := config.SigSigningInterval.Nanoseconds()
	pshardWaitInterval := config.SigSigningInterval.Nanoseconds()
	if len(shards) != 0 {
		shardWaitInterval /= int64(len(shards))
	}
	if len(pshards) != 0 {
		pshardWaitInterval /= int64(len(pshards))
	}
	for _, assertion := range zone.Content {
		assertion.AddSig(signature)
		signature.ValidSince += assertionWaitInterval / int64(time.Second)
		signature.ValidUntil += assertionWaitInterval / int64(time.Second)
	}
	signature.ValidSince = config.SigValidSince
	signature.ValidUntil = config.SigValidUntil
	for _, shard := range shards {
		if config.AddSigMetaDataToPshards {
			shard.AddSig(signature)
			signature.ValidSince += shardWaitInterval / int64(time.Second)
			signature.ValidUntil += shardWaitInterval / int64(time.Second)
		}
	}
	signature.ValidSince = config.SigValidSince
	signature.ValidUntil = config.SigValidUntil
	for _, pshard := range pshards {
		if config.AddSigMetaDataToPshards {
			pshard.AddSig(signature)
			signature.ValidSince += pshardWaitInterval / int64(time.Second)
			signature.ValidUntil += pshardWaitInterval / int64(time.Second)
		}
	}
}

//isConsistent performs the checks specified in config
func isConsistent(zone *section.Zone, shards []*section.Shard, pshards []*section.Pshard,
	config ConsistencyConfig) bool {
	if !doConsistencyCheck(zone, config) {
		return false
	}
	for _, shard := range shards {
		if !doConsistencyCheck(shard, config) {
			return false
		}
	}
	for _, pshard := range pshards {
		if !doConsistencyCheck(pshard, config) {
			return false
		}
	}
	return true
}

//doConsistencyCheck returns true if section is consistent
func doConsistencyCheck(section section.WithSigForward, config ConsistencyConfig) bool {
	if config.DoConsistencyCheck {
		if !siglib.ValidSectionAndSignature(section) {
			log.Error("zone content is not consistent")
			return false
		}
	} else {
		if config.SortShards {
			section.Sort()
		}
		if config.CheckStringFields {
			if !siglib.CheckStringFields(section) {
				log.Error("zone content is not consistent")
				return false
			}
		}
		if config.SigNotExpired {
			if !siglib.CheckSignatureNotExpired(section) {
				log.Error("zone content is not consistent")
				return false
			}
		}
	}
	return true
}

func signZoneContent(zone *section.Zone, shards []*section.Shard, pshards []*section.Pshard,
	keyPath string) error {
	keys, err := LoadPrivateKeys(keyPath)
	if err != nil {
		return errors.New("Was not able to load private keys")
	}
	if err := signZone(zone, keys); err != nil {
		return err
	}
	for _, shard := range shards {
		if err := signShard(shard, keys); err != nil {
			return err
		}
	}
	for _, pshard := range pshards {
		if err := signSection(pshard, keys); err != nil {
			return err
		}
	}
	return nil
}

//publishZone publishes the zone's content either to the specified authoritative servers or to a
//file in zonefile format.
func (r *Rainspub) publishZone(zoneContent []section.Section, config Config) {
	if config.DoPublish {
		//TODO check if zone is not too large. If it is, split it up and send
		//content separately.
		log.Debug("published zone", "zone", zoneContent)
		msg := message.Message{
			Token:        token.New(),
			Content:      zoneContent,
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
