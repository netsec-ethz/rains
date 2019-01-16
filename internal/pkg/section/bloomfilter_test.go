package section

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/object"
)

func TestBloomFilter(t *testing.T) {
	var tests = []struct {
		input BloomFilter
	}{
		{BloomFilter{BloomKM12, algorithmTypes.Shake256, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM12, algorithmTypes.Fnv64, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM12, algorithmTypes.Fnv128, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM16, algorithmTypes.Fnv128, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM16, algorithmTypes.Shake256, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM16, algorithmTypes.Fnv64, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM20, algorithmTypes.Fnv128, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM20, algorithmTypes.Shake256, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM20, algorithmTypes.Fnv64, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM24, algorithmTypes.Fnv128, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM24, algorithmTypes.Shake256, make(bitarray.BitArray, 16)}},
		{BloomFilter{BloomKM24, algorithmTypes.Fnv64, make(bitarray.BitArray, 16)}},
	}
	for _, test := range tests {
		test.input.Add("testName", "testZone", "testContext", object.OTIP4Addr)
		if ok, err := test.input.Contains("testName", "testZone", "testContext", object.OTIP4Addr); err != nil || !ok {
			t.Fatal("Filter should contain this element")
		}
		if ok, err := test.input.Contains("testName", "testZone", "testContext", object.OTIP6Addr); err != nil || ok {
			t.Fatal("Filter should not contain this element")
		}
	}
}

func TestBloomFilterCompareTo(t *testing.T) {
	bfs := sortedBloomFilters(10)
	shuffled := append([]BloomFilter{}, bfs...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].CompareTo(shuffled[j]) < 0
	})
	for i, a := range bfs {
		if a.CompareTo(shuffled[i]) != 0 {
			t.Fatal("Not sorted correctly")
		}
	}
}
