package evaluation

import (
	"bytes"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

// PshardSpaceSaving expects as input a path to a zonefile containing one zone
// that contains assertions. It returns the number of bytes that can be saved by
// using a pshard instead of a normal shard. The space saved depends on the
// guaranteed false positive rate. There is a tradeoff between saved space and
// computing time due to the number of hash function that must be executed per
// assertion.
func PshardSpaceSaving(zonefileName string, bfByteSize int) int {
	log.Root().SetHandler(log.DiscardHandler())
	parser := new(zonefile.Parser)
	zone, err := parser.LoadZone(zonefileName)
	if err != nil {
		log.Error(err.Error())
		return -1
	}
	shard := section.Shard{
		Context:     zone.Context,
		SubjectZone: zone.SubjectZone,
	}
	bf := section.BloomFilter{
		ModeOfOperation:  section.KirschMitzenmacher1,
		NofHashFunctions: 5,
		HashFamily:       []algorithmTypes.Hash{algorithmTypes.Murmur364},
		Filter:           make(bitarray.BitArray, bfByteSize),
	}
	pshard := section.Pshard{
		Context:     zone.Context,
		SubjectZone: zone.SubjectZone,
		Datastructure: section.DataStructure{
			Type: section.BloomFilterType,
			Data: bf,
		},
	}
	for _, s := range zone.Content {
		switch a := s.(type) {
		case *section.Assertion:
			shard.Content = append(shard.Content, a)
		}
	}
	encShard := new(bytes.Buffer)
	shard.MarshalCBOR(cbor.NewCBORWriter(encShard))
	encPshard := new(bytes.Buffer)
	pshard.MarshalCBOR(cbor.NewCBORWriter(encPshard))
	return len(encShard.Bytes()) - len(encPshard.Bytes())
}
