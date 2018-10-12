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
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"golang.org/x/crypto/ed25519"
)

var privateKeys map[string]ed25519.PrivateKey

func init() {
	privateKeys = make(map[string]ed25519.PrivateKey)
}

func LeafZone(fileName, zoneName, context string, size int) {
	zone, err := Zone(zoneName, context, size, Leaf, ZoneAsNegProof, publisher.ShardingConfig{}, publisher.PShardingConfig{})
	if err != nil {
		panic(err.Error())
	}
	err = zonefile.Parser{}.EncodeAndStore(fileName, zone)
	if err != nil {
		panic(err.Error())
	}
}

func DelegationZone(fileName, zoneName, context string, zoneSize, maxShardSize int, namesPerPshard, probBound float64) {
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
	zone, err := Zone(zoneName, context, zoneSize, Delegation, ShardAndPshard, sconf, pconf)
	if err != nil {
		panic(err.Error())
	}
	err = zonefile.Parser{}.EncodeAndStore(fileName, zone)
	if err != nil {
		panic(err.Error())
	}
}

func Zone(zoneName, context string, size int, objDistr ObjTypeDistr,
	negProofs NonExistProofs, shardingConf publisher.ShardingConfig,
	pshardingConf publisher.PShardingConfig) (*section.Zone, error) {
	zone := &section.Zone{
		Context:     context,
		SubjectZone: zoneName,
	}
	nextName := nameSeq("../../data/names.txt")
	assertions := make([]*section.Assertion, size)
	for i := 0; i < size; i++ {
		names, objs := nextObject(objDistr, nextName(), zoneName)
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
			return nil, err
		}
		pshards, err := publisher.DoPsharding(context, zoneName, assertions, nil, pshardingConf, true)
		if err != nil {
			return nil, err
		}
		publisher.CreateZone(zone, nil, shards, pshards)
	case ZoneAsNegProof:
		publisher.CreateZone(zone, assertions, nil, nil)
	default:
		return nil, errors.New("unsupported nonExistProofs identifier")
	}
	return zone, nil
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

func nextObject(objDistr ObjTypeDistr, name, zoneName string) ([]string, []object.Object) {
	switch objDistr {
	case Delegation:
		return delegationObject(name, zoneName)
	case Leaf:
		return []string{name}, leafObject()
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

func delegationObject(name, zoneName string) ([]string, []object.Object) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	privateKeys[fmt.Sprintf("%s.%s", name, zoneName)] = privKey
	names := []string{name, name, "ns." + name, "ns1." + name}
	objs := make([]object.Object, 4)
	objs[0] = object.Object{
		Type: object.OTDelegation,
		Value: keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: algorithmTypes.Ed25519,
				KeyPhase:  1,
				KeySpace:  keys.RainsKeySpace,
			},
			ValidSince: time.Now().Unix(),
			ValidUntil: time.Now().Add(365 * 24 * time.Hour).Unix(),
			Key:        pubKey,
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
	return names, objs
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
