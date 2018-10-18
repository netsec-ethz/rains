package generate

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"golang.org/x/crypto/ed25519"
)

//Zones creates a number of zone files and returns the names of all leaf zones.
func Zones(nofTLDs, nofSLD, leafZoneSize int, path, rootAddr string) ([]NameIPAddr, []NameType) {
	//create root zone
	leafNames := []NameType{}
	names := DelegationZone(path+"root.txt", ".", ".", 4*nofTLDs, 500, 10, 10000000)
	//create TLDs
	newNames := []NameIPAddr{}
	for _, name := range names {
		newNames = append(newNames, DelegationZone(path+name.Name+"txt", name.Name, ".", 4*nofSLD, 500, 10, 10000000)...)
	}
	//create second level leaf zones
	for _, name := range newNames {
		leafNames = append(leafNames, LeafZone(path+name.Name+"txt", name.Name, ".", leafZoneSize)...)
	}
	newNames = append(newNames, names...)
	newNames = append(newNames, NameIPAddr{"root", rootAddr})
	//TODO create TLD that delegates all of its commercial names to co.TLDName
	return newNames, leafNames
}

func LeafZone(fileName, zoneName, context string, zoneSize int) []NameType {
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
	probBound float64) []NameIPAddr {
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
	probBound float64) ([]NameIPAddr, []NameType) {
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
	*section.Zone, []NameIPAddr, []NameType, error) {
	delegNames := []NameIPAddr{}
	leafNames := []NameType{}
	zone := &section.Zone{
		Context:     context,
		SubjectZone: zoneName,
	}
	nextName := nameSeq("../../data/names.txt")
	assertions := make([]*section.Assertion, leafSize+delegSize)
	for i := 0; i < leafSize; i++ {
		names, objs, _ := nextObject(Leaf, nextName(), zoneName)
		if zoneName == "." {
			leafNames = append(leafNames, NameType{Name: names[0] + ".", Type: objs[0].Type})
		} else {
			leafNames = append(leafNames, NameType{Name: names[0] + "." + zoneName, Type: objs[0].Type})
		}
		assertions[i] = &section.Assertion{
			SubjectName: names[0],
			Content:     objs,
		}
	}
	for i := leafSize; i < leafSize+delegSize; i++ {
		names, objs, privKey := nextObject(Delegation, nextName(), zoneName)
		storePrivateKey("keys/privateKey"+names[0]+".txt", privKey)
		if zoneName == "." {
			delegNames = append(delegNames, NameIPAddr{Name: names[0] + ".", IPAddr: objs[3].Value.(string)})
		} else {
			delegNames = append(delegNames, NameIPAddr{Name: names[0] + "." + zoneName, IPAddr: objs[3].Value.(string)})
		}

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

func nextObject(objDistr ObjTypeDistr, name, zoneName string) ([]string, []object.Object, keys.PrivateKey) {
	switch objDistr {
	case Delegation:
		return delegationObject(name, zoneName)
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

func delegationObject(name, zoneName string) ([]string, []object.Object, keys.PrivateKey) {
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

func storePrivateKey(path string, privateKey keys.PrivateKey) {
	encoding, err := json.Marshal([]keys.PrivateKey{privateKey})
	if err != nil {
		panic(err)
	}
	if ioutil.WriteFile(path, encoding, 0600) != nil {
		panic(err)
	}
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
