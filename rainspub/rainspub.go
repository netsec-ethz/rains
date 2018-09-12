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
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
)

//Init starts the zone information publishing process according to the provided config.
func Init(inputConfig Config) {
	config = inputConfig
	parser = zoneFileParser.Parser{}
	signatureEncoder = zoneFileParser.Parser{}
	publish()
}

//publish calls the relevant library function to publish information according to the provided
//config during initialization.
//FIXME CFE this implementation assumes that there is exactly one zone per zonefile.
func publish() {
	zone, err := loadZonefile()
	if err != nil {
		return
	}
	if config.DoSharding {
		assertions, shards, err := splitZoneContent(zone)
		if err != nil {
			return
		}
		var newShards []*rainslib.ShardSection
		if config.MaxShardSize > 0 {
			newShards = groupAssertionsToShardsBySize(zone.SubjectZone, zone.Context, assertions,
				config.SortShards)
		} else if config.NofAssertionsPerShard > 0 {
			newShards = groupAssertionsToShardsByNumber(zone.SubjectZone, zone.Context, assertions,
				config.SortShards)
		} else {
			log.Error("MaxShardSize or NofAssertionsPerShard must be positive when DoSharding is set")
			return
		}
		if len(shards) != 0 {
			shards = append(shards, newShards...)
			sort.Slice(shards, func(i, j int) bool { return shards[i].CompareTo(shards[j]) < 0 })
		} else {
			shards = newShards
		}
	}
	if config.AddSignatureMetaData {
		//TODO CFE where to add signature meta data and spreading it uniformly over given interval.
		//addSignatureMetaData()
	}
	if config.DoConsistencyCheck {
		//consistencyCheck()
	}
	//TODO CFE add other two consistency checks
	if config.SortShards {
		//sort shards
	}
	if config.DoSigning {
		//sign section
	}
	if config.OutputPath != "" {
		parser := zoneFileParser.Parser{}
		encoding := parser.Encode(zone)
		ioutil.WriteFile(config.OutputPath, []byte(encoding), 0600)
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
		}
	}
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
			}
		default:
			log.Error("Invalid zone content", "section", s)
			return nil, nil, errors.New("Invalid zone content")
		}
	}
	return assertions, shards, nil
}

func groupAssertionsToShardsBySize(subjectZone, context string,
	assertions []*rainslib.AssertionSection, doSort bool) []*rainslib.ShardSection {
	return nil
}

//groupAssertionsToShardsByNumber creates shards containing a maximum number of different assertion
//names according to the configuration. Before grouping the assertions, it sorts them. It returns a
//zone section containing the created shards. The contained shards and assertions still have non
//empty subjectZone and context values as these values are needed to generate a signatures
func groupAssertionsToShardsByNumber(subjectZone, context string,
	assertions []*rainslib.AssertionSection, doSort bool) []*rainslib.ShardSection {
	if doSort {
		sort.Slice(assertions, func(i, j int) bool { return assertions[i].CompareTo(assertions[j]) < 0 })
	}
	shards := []*rainslib.ShardSection{}
	nameCount := 0
	prevAssertionSubjectName := ""
	prevShardAssertionSubjectName := ""
	shard := newShard(subjectZone, context)
	for i, a := range assertions {
		if a.SubjectZone != subjectZone || a.Context != context {
			log.Error("assertion's subjectZone or context does not match with the zone's", "assertion", a)
		}
		if prevAssertionSubjectName != a.SubjectName {
			nameCount++
			prevAssertionSubjectName = a.SubjectName
		}
		if nameCount > config.NofAssertionsPerShard {
			shard.RangeFrom = prevShardAssertionSubjectName
			shard.RangeTo = a.SubjectName
			shards = append(shards, shard)
			nameCount = 1
			shard = newShard(subjectZone, context)
			prevShardAssertionSubjectName = assertions[i-1].SubjectName
		}
		shard.Content = append(shard.Content, a)
	}
	shard.RangeFrom = prevShardAssertionSubjectName
	shard.RangeTo = ""
	shards = append(shards, shard)
	return shards
}

func newShard(subjectZone, context string) *rainslib.ShardSection {
	return &rainslib.ShardSection{
		SubjectZone: subjectZone,
		Context:     context,
		Content:     []*rainslib.AssertionSection{},
	}
}

//publishZone performs the following steps:
//1) Loads the rains zone file.
//2) Adds Signature MetaData and perform consistency checks on the zone and its
//   signatures
//3) Let rainspub sign the zone
//4) Query the superordinate zone for the new delegation and push it to all
//   rains servers
//5) After rainspub signed the zone, send the signed zone to all rains servers
//   specified in the config
//returns an error if something goes wrong
/*func publishZone(keyPhase int) error {

	//TODO CFE be able to add multiple signature to a section
	addSignatureMetaData(zone, keyPhase)
	if ConsistencyCheck(zone) {
		return errors.New("Inconsistent section")
	}
	//TODO CFE do this in a go routine
	if err = SignSectionUnsafe(zone, keyPhaseToPath); err != nil {
		return err
	}
	//TODO CFE: query new delegation from superordinate server and push them to all rains servers
	msg, err := CreateRainsMessage(zone)
	if err != nil {
		log.Warn("Was not able to parse the zone to a rains message.", "error", err)
		return err
	}
	connErrors := PublishSections(msg, config.ServerAddresses)
	for _, connErr := range connErrors {
		log.Warn("Was not able to send signed zone to this server.", "server", connErr.TCPAddr.String())
		//TODO CFE: Implement error handling
	}
	return nil
}
*/
//TODO CFE change it such that it can be used as envisioned in the
//design-scalable-signature-updates.md
//especially that not all assertions are expiring at the same time
func addSignatureMetaData(zone *rainslib.ZoneSection, keyPhase int) {
	//TODO CFE consider from config, validUntil, validSince, duration
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: rainslib.Ed25519,
			KeySpace:  rainslib.RainsKeySpace,
			KeyPhase:  keyPhase,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Unix(),
	}
	zone.AddSig(signature)
	for _, sec := range zone.Content {
		switch sec := sec.(type) {
		case *rainslib.AssertionSection:
			if sec.Content[0].Type == rainslib.OTDelegation {
				signature.ValidSince = time.Now().Unix()
				signature.ValidUntil = time.Now().Unix()
			} else {
				signature.ValidSince = time.Now().Unix()
				signature.ValidUntil = time.Now().Unix()
			}
		case *rainslib.ShardSection:
			signature.ValidSince = time.Now().Unix()
			signature.ValidUntil = time.Now().Unix()
		default:
			log.Error("Invalid zone content")
		}
		sec.AddSig(signature)
	}
}

//consistencyCheck returns true if there are no inconsistencies in the section. It
//also makes sure that the section is sorted
func consistencyCheck(section rainslib.MessageSectionWithSig) bool {
	//TODO consider config.SigNotExpired and config.checkStringFields
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		return rainsSiglib.ValidSectionAndSignature(section)
	case *rainslib.ShardSection:
		return shardConsistencyCheck(section)
	case *rainslib.ZoneSection:
		if !rainsSiglib.ValidSectionAndSignature(section) {
			return false
		}
		for _, sec := range section.Content {
			switch sec := sec.(type) {
			case *rainslib.AssertionSection:
				if !rainsSiglib.ValidSectionAndSignature(sec) {
					return false
				}
			case *rainslib.ShardSection:
				if !shardConsistencyCheck(sec) {
					return false
				}
			default:
				log.Error("Invalid zone content", "zone", section)
				return false
			}
		}
	case *rainslib.AddressAssertionSection:
		log.Warn("Not yet implemented")
		return false
	default:
		log.Error("Invalid section type")
		return false
	}
	return true
}

//shardConsistencyCheck returns true if the shard and all contained
//assertions are consistent and sorted
func shardConsistencyCheck(shard *rainslib.ShardSection) bool {
	if !rainsSiglib.ValidSectionAndSignature(shard) {
		return false
	}
	for _, a := range shard.Content {
		if !rainsSiglib.ValidSectionAndSignature(a) {
			return false
		}
	}
	return true
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
