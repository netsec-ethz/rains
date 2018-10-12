package generate

import (
	"errors"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

func Zonefile(fileName, zoneName, context string, size int, objDistr ObjTypeDistr,
	negProofs NonExistProofs, shardingConf publisher.ShardingConfig,
	pshardingConf publisher.PShardingConfig) error {
	zone := &section.Zone{
		Context:     context,
		SubjectZone: zoneName,
	}
	assertions := make([]*section.Assertion, size)
	for i := 0; i < size; i++ {
		assertions[i] = &section.Assertion{
			SubjectName: nextName(),
			Content:     nextObject(objDistr),
		}
	}
	switch negProofs {
	case ShardAndPshard:
		shards, err := publisher.DoSharding(context, zoneName, assertions, nil, shardingConf, true)
		if err != nil {
			return err
		}
		pshards, err := publisher.DoPsharding(context, zoneName, assertions, nil, pshardingConf, true)
		if err != nil {
			return err
		}
		publisher.CreateZone(zone, assertions, shards, pshards)
	case Zone:
		publisher.CreateZone(zone, assertions, nil, nil)
	default:
		return errors.New("unsupported nonExistProofs identifier")
	}

	err := zonefile.Parser{}.EncodeAndStore("zonefiles/"+fileName, zone)
	if err != nil {
		return err
	}
	return nil
}

func nextName() string {
	return ""
}

func nextObject(objDistr ObjTypeDistr) []object.Object {
	return []object.Object{}
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
	Zone NonExistProofs = iota
	ShardAndPshard
)
