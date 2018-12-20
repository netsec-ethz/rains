package section

import (
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/object"
)

func TestBloomFilter(t *testing.T) {
	filter := BloomFilter{
		Algorithm: BloomKM12,
		Hash:      algorithmTypes.Shake256,
		Filter:    make(bitarray.BitArray, 16),
	}
	filter.Add("testName", "testZone", "testContext", object.OTIP4Addr)
	if ok, err := filter.Contains("testName", "testZone", "testContext", object.OTIP4Addr); err != nil || !ok {
		t.Fatal("Filter should contain this element")
	}
	if ok, err := filter.Contains("testName", "testZone", "testContext", object.OTIP6Addr); err != nil || ok {
		t.Fatal("Filter should not contain this element")
	}
	filter.Hash = algorithmTypes.Fnv64
	filter.Filter = make(bitarray.BitArray, 16)
	filter.Add("testName", "testZone", "testContext", object.OTIP4Addr)
	if ok, err := filter.Contains("testName", "testZone", "testContext", object.OTIP4Addr); err != nil || !ok {
		t.Fatal("Filter should contain this element")
	}
	if ok, err := filter.Contains("testName", "testZone", "testContext", object.OTServiceInfo); err != nil || ok {
		t.Fatal("Filter should not contain this element.")
	}
	filter.Hash = algorithmTypes.Fnv128
	filter.Filter = make(bitarray.BitArray, 16)
	filter.Add("testName", "testZone", "testContext", object.OTIP4Addr)
	if ok, err := filter.Contains("testName", "testZone", "testContext", object.OTIP4Addr); err != nil || !ok {
		t.Fatal("Filter should contain this element")
	}
	if ok, err := filter.Contains("testName", "testZone", "testContext", object.OTServiceInfo); err != nil || ok {
		t.Fatal("Filter should not contain this element.")
	}

}
