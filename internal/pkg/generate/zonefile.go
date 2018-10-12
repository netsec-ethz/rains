package generate

import (
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
)

func Zonefile(fileName, zoneName string, size, depth int, objDistr ObjTypeDistr,
	negProofs NonExistProofs, shardingConf publisher.ShardingConfig,
	pshardingConf publisher.PShardingConfig) {

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
