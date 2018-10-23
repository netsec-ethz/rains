package generate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/simulation"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"github.com/netsec-ethz/rains/tools/keycreator"
	"golang.org/x/crypto/ed25519"
)

//Zones creates a number of zone files and returns the names of all leaf zones.
func Zones(config simulation.Config) ([]simulation.NameIPAddr, []simulation.NameType, [][]simulation.NameType, map[string]int) {
	allLeafNames := []simulation.NameType{}
	leafNames := make([][]simulation.NameType, config.RootZone.Size)
	delegNames := []simulation.NameIPAddr{simulation.NameIPAddr{config.RootZone.Name, config.RootIPAddr}}
	tldNames := createRootZone(config)
	zoneToContinent := ZoneIPToContinent(tldNames, config)
	nameToTLD := make(map[string]int)

	//create TLDs
	sldNames := []simulation.NameIPAddr{}
	nofNamesPerTLD := namesPerTLD(config)
	for i, name := range tldNames {
		newNames := DelegationZone(fmt.Sprintf("%s%s.txt", config.Paths.ZonefilePath, name.Name),
			name.Name, ".", 4*nofNamesPerTLD[i], config.TLDZones.MaxShardSize,
			config.TLDZones.NofAssertionsPerPshard, config.TLDZones.ProbabilityBound)
		for _, n := range newNames {
			zoneToContinent[n.IPAddr] = zoneToContinent[name.IPAddr]
			nameToTLD[n.Name] = i
		}
		sldNames = append(sldNames, newNames...)
	}
	delegNames = append(delegNames, tldNames...)

	//create leaf and hybrid zones
	zipf := rand.NewZipf(rand.New(rand.NewSource(config.Zipfs.LeafZoneSize.Seed)), config.Zipfs.LeafZoneSize.S, 1, config.Zipfs.LeafZoneSize.Size)
	for len(sldNames) != 0 {
		delegNames = append(delegNames, sldNames...)
		nextNames := []simulation.NameIPAddr{}
		for _, name := range sldNames {
			if rand.Intn(101) < config.IsLeafZone {
				newLeafNames := LeafZone(fmt.Sprintf("%s%s.txt", config.Paths.ZonefilePath, name.Name),
					name.Name, ".", 1+int(zipf.Uint64()))
				leafNames[nameToTLD[name.Name]] = append(leafNames[nameToTLD[name.Name]], newLeafNames...)
				allLeafNames = append(allLeafNames, newLeafNames...)
			} else {
				newNextNames, newLeafNames := HybridZone(fmt.Sprintf("%s%s.txt", config.Paths.ZonefilePath, name.Name),
					name.Name, ".", int(zipf.Uint64()), int(zipf.Uint64()), config.HybridZones.MaxShardSize,
					config.HybridZones.NofAssertionsPerPshard, config.HybridZones.ProbabilityBound)
				for _, n := range newNextNames {
					zoneToContinent[n.IPAddr] = zoneToContinent[name.IPAddr]
					nameToTLD[n.Name] = nameToTLD[name.Name]
				}
				nextNames = append(nextNames, newNextNames...)
				leafNames[nameToTLD[name.Name]] = append(leafNames[nameToTLD[name.Name]], newLeafNames...)
				allLeafNames = append(allLeafNames, newLeafNames...)
			}
		}
		sldNames = nextNames
	}
	return delegNames, allLeafNames, leafNames, zoneToContinent
}

func LeafZone(fileName, zoneName, context string, zoneSize int) []simulation.NameType {
	zone, _, nameTypes, err := Zone(zoneName, context, zoneSize, 0, ZoneAsNegProof, publisher.ShardingConfig{}, publisher.PShardingConfig{})
	if err != nil {
		panic(err.Error())
	}
	err = zonefile.Parser{}.EncodeAndStore(fileName, zone)
	if err != nil {
		panic(err.Error())
	}
	return nameTypes
}

func DelegationZone(fileName, zoneName, context string, zoneSize, maxShardSize int, namesPerPshard,
	probBound float64) []simulation.NameIPAddr {
	sconf, pconf := shardingConf(zoneSize, maxShardSize, namesPerPshard, probBound)
	zone, names, _, err := Zone(zoneName, context, 0, zoneSize, ShardAndPshard, sconf, pconf)
	if err != nil {
		panic(err.Error())
	}
	err = zonefile.Parser{}.EncodeAndStore(fileName, zone)
	if err != nil {
		panic(err.Error())
	}
	return names
}

func HybridZone(fileName, zoneName, context string, leafSize, delegSize, maxShardSize int, namesPerPshard,
	probBound float64) ([]simulation.NameIPAddr, []simulation.NameType) {
	sconf, pconf := shardingConf(leafSize+delegSize, maxShardSize, namesPerPshard, probBound)
	zone, delegNames, leafNames, err := Zone(zoneName, context, leafSize, delegSize, ShardAndPshard, sconf, pconf)
	if err != nil {
		panic(err.Error())
	}
	err = zonefile.Parser{}.EncodeAndStore(fileName, zone)
	if err != nil {
		panic(err.Error())
	}
	return delegNames, leafNames
}

//Zone creates and stores a zonefile according to the given configuration. It returns the names of
//all delegation assertions and leaf assertions in to separate slices.
func Zone(zoneName, context string, leafSize, delegSize int, negProofs NonExistProofs,
	shardingConf publisher.ShardingConfig, pshardingConf publisher.PShardingConfig) (
	*section.Zone, []simulation.NameIPAddr, []simulation.NameType, error) {
	delegNames := []simulation.NameIPAddr{}
	leafNames := []simulation.NameType{}
	zone := &section.Zone{
		Context:     context,
		SubjectZone: zoneName,
	}
	nextName := nameSeq("../../data/names.txt")
	assertions := make([]*section.Assertion, leafSize+delegSize)
	for i := 0; i < leafSize; i++ {
		names, objs, _ := nextObject(Leaf, nextName())
		if zoneName == "." {
			leafNames = append(leafNames, simulation.NameType{Name: names[0] + ".", Type: objs[0].Type})
		} else {
			leafNames = append(leafNames, simulation.NameType{Name: names[0] + "." + zoneName, Type: objs[0].Type})
		}
		assertions[i] = &section.Assertion{
			SubjectName: names[0],
			Content:     objs,
		}
	}
	for i := leafSize; i < leafSize+delegSize; i++ {
		names, objs, privKey := nextObject(Delegation, nextName())
		name := names[0] + "."
		if zoneName != "." {
			name += zoneName
		}
		delegNames = append(delegNames, simulation.NameIPAddr{Name: name, IPAddr: objs[3].Value.(string)})
		publisher.StorePrivateKey(fmt.Sprintf("keys/privateKey%s.txt", name), []keys.PrivateKey{privKey})

		for j, obj := range objs {
			assertions[i] = &section.Assertion{
				SubjectName: names[j],
				Content:     []object.Object{obj},
			}
			i++
		}
		i--
	}
	switch negProofs {
	case ShardAndPshard:
		shards, err := publisher.DoSharding(context, zoneName, assertions, nil, shardingConf, true)
		if err != nil {
			return nil, nil, nil, err
		}
		pshards, err := publisher.DoPsharding(context, zoneName, assertions, nil, pshardingConf, true)
		if err != nil {
			return nil, nil, nil, err
		}
		publisher.CreateZone(zone, nil, shards, pshards)
	case ZoneAsNegProof:
		publisher.CreateZone(zone, assertions, nil, nil)
	default:
		return nil, nil, nil, errors.New("unsupported nonExistProofs identifier")
	}
	return zone, delegNames, leafNames, nil
}

func nameSeq(path string) func() string {
	i := -1
	names := LoadNames(path)
	j := -1
	return func() string {
		if len(names)-1 == i {
			j++
			i = -1
		}
		i++
		if j == -1 {
			return names[i]
		}
		return fmt.Sprintf("%s-%s", names[j], names[i])
	}
}

//LoadNames returns a slice of unique names loaded from path
func LoadNames(path string) []string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Was not able to read file : %s", err.Error()))
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanWords)
	var names []string
	for scanner.Scan() {
		names = append(names, scanner.Text())
	}
	return names
}

func nextObject(objDistr ObjTypeDistr, name string) ([]string, []object.Object, keys.PrivateKey) {
	switch objDistr {
	case Delegation:
		return delegationObject(name)
	case Leaf:
		return []string{name}, leafObject(), keys.PrivateKey{}
	default:
		panic("unsupported objTypedistribution identifier")
	}
}

func leafObject() []object.Object {
	if rand.Intn(2) == 0 {
		return []object.Object{object.Object{
			Type:  object.OTIP4Addr,
			Value: fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)),
		}}
	}
	return []object.Object{object.Object{
		Type: object.OTIP6Addr,
		Value: fmt.Sprintf("2001:db8::%d%d%d%d:%d%d%d%d", rand.Intn(10), rand.Intn(10), rand.Intn(10),
			rand.Intn(10), rand.Intn(10), rand.Intn(10), rand.Intn(10), rand.Intn(10)),
	}}
}

func delegationObject(name string) ([]string, []object.Object, keys.PrivateKey) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	names := []string{name, name, "ns." + name, "ns1." + name}
	objs := make([]object.Object, 4)
	publicKeyID := keys.PublicKeyID{
		Algorithm: algorithmTypes.Ed25519,
		KeyPhase:  1,
		KeySpace:  keys.RainsKeySpace,
	}
	objs[0] = object.Object{
		Type: object.OTDelegation,
		Value: keys.PublicKey{
			PublicKeyID: publicKeyID,
			ValidSince:  time.Now().Unix(),
			ValidUntil:  time.Now().Add(365 * 24 * time.Hour).Unix(),
			Key:         pubKey,
		},
	}
	objs[1] = object.Object{
		Type:  object.OTRedirection,
		Value: "ns." + name,
	}
	objs[2] = object.Object{
		Type: object.OTServiceInfo,
		Value: object.ServiceInfo{
			Name:     "ns1." + name,
			Port:     5022,
			Priority: 0,
		},
	}
	objs[3] = object.Object{
		Type:  object.OTIP4Addr,
		Value: fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)),
	}
	return names, objs, keys.PrivateKey{PublicKeyID: publicKeyID, Key: privKey}
}

func shardingConf(zoneSize, maxShardSize int, namesPerPshard, probBound float64) (
	publisher.ShardingConfig, publisher.PShardingConfig) {
	//FIXME CFE namesPerPshard is used to calculate the filter parameters, but assertions per pshard
	//should be used to have the correct probability bound!!!
	filterSize := math.Ceil(namesPerPshard * math.Log(1/probBound) / math.Log(1/math.Pow(2, math.Log(2))))
	nofHashFunction := math.Round((filterSize / namesPerPshard) * math.Log(2))
	if zoneSize%4 != 0 {
		panic("size must be a multiple of 4")
	}
	sconf := publisher.ShardingConfig{
		DoSharding:   true,
		MaxShardSize: maxShardSize,
	}
	pconf := publisher.PShardingConfig{
		DoPsharding:            true,
		NofAssertionsPerPshard: int(namesPerPshard),
		BloomFilterConf: publisher.BloomFilterConfig{
			BFOpMode:         section.KirschMitzenmacher1,
			Hashfamily:       []algorithmTypes.Hash{algorithmTypes.Murmur364},
			NofHashFunctions: int(nofHashFunction),
			BloomFilterSize:  int(filterSize),
		},
	}
	return sconf, pconf
}

func createRootZone(config simulation.Config) []simulation.NameIPAddr {
	keycreator.DelegationAssertion(".", ".", config.Paths.RootDelegAssertionFilePath,
		fmt.Sprintf("%s%s%s.txt", config.Paths.KeysPath, config.Paths.PrivateKeyFileNamePrefix, config.RootZone.Name))
	return DelegationZone(fmt.Sprintf("%s%s.txt", config.Paths.ZonefilePath, config.RootZone.Name),
		".", ".", 4*config.RootZone.Size, config.RootZone.MaxShardSize,
		config.RootZone.NofAssertionsPerPshard, config.RootZone.ProbabilityBound)
}

func namesPerTLD(config simulation.Config) []int {
	result := make([]int, config.RootZone.Size)
	zipf := rand.NewZipf(rand.New(rand.NewSource(config.Zipfs.Root.Seed)), config.Zipfs.Root.S, 1, uint64(config.RootZone.Size-1))
	for ; config.NofSLDs > 0; config.NofSLDs-- {
		result[int(zipf.Uint64())]++
	}
	return result
}

func ZoneIPToContinent(tlds []simulation.NameIPAddr, config simulation.Config) map[string]int {
	zoneToContinent := make(map[string]int)
	zipf := rand.NewZipf(rand.New(rand.NewSource(config.Zipfs.TLDContinent.Seed)), config.Zipfs.TLDContinent.S, 1, config.Zipfs.TLDContinent.Size)
	for _, tld := range tlds {
		zoneToContinent[tld.IPAddr] = int(zipf.Uint64())
	}
	return zoneToContinent
}

//ObjTypeDistr is an enumeration of object type distributions
type ObjTypeDistr int

const (
	//Delegation determines the object type distribution of a delegation zone
	Delegation ObjTypeDistr = iota
	//Leaf determines the object type distribution of a leaf zone
	Leaf
)

//NonExistProofs is an enumeration of a zone's possibilities to proof nonexistence
type NonExistProofs int

const (
	ZoneAsNegProof NonExistProofs = iota
	ShardAndPshard
)
