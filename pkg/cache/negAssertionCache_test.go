package cache

import (
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

func TestNegAssertionCache(t *testing.T) {
	var tests = []struct {
		input NegativeAssertion
	}{
		//Warn when there are 4 entries in the cache. Replace one/some if there is a 5th added.
		{
			&NegAssertionImpl{
				cache:   lruCache.New(),
				counter: safeCounter.New(4),
				zoneMap: safeHashMap.New(),
			},
		},
	}
	for i, test := range tests {
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		shards := getShards()
		zones := getZones()
		//Test add
		if ok := c.AddZone(zones[2], zones[2].ValidUntil(), true); !ok || c.Len() != 1 {
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 1, c.Len())
		}

		if ok := c.AddShard(shards[3], shards[3].ValidUntil(), false); !ok || c.Len() != 2 {
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 2, c.Len())
		}

		if ok := c.AddZone(zones[0], zones[0].ValidUntil(), false); !ok || c.Len() != 3 {
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}

		if ok := c.AddShard(shards[1], shards[1].ValidUntil(), false); ok || c.Len() != 3 {
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}

		//Test Get
		//external elements
		s, ok := c.Get(zones[0].SubjectZone, zones[0].Context, shards[2])
		if !ok || len(s) != 1 || zones[0] != s[0] {
			t.Errorf("%d:Was not able to get correct section from cache expected=%s actual=%s", i, zones[0], s)
		}
		//internal element
		s, ok = c.Get(zones[2].SubjectZone, zones[2].Context, zones[2])
		if !ok || len(s) != 1 || zones[2] != s[0] {
			t.Errorf("%d:Was not able to get correct assertion from cache expected=%s actual=%s", i, zones[2], s)
		}
		//more than one answer
		s, ok = c.Get(zones[0].SubjectZone, zones[0].Context, zones[0])
		if !ok || len(s) != 2 || (s[0] == zones[0] && s[1] != shards[1]) ||
			(s[0] == shards[1] && s[1] != zones[0]) || (s[0] == zones[0] && s[0] == shards[1]) {
			t.Errorf("%d:Was not able to get correct assertion from cache actual=%s", i, s)
		}
		//Test RemoveZone internal
		c.RemoveZone("org")
		if c.Len() != 2 {
			t.Errorf("%d:Was not able to remove elements of zone 'org' from cache.", i)
		}
		s, ok = c.Get(zones[0].SubjectZone, zones[0].Context, zones[0])
		if !ok || len(s) != 2 {
			t.Errorf("%d:Was not able to remove correct elements of zone 'org' from cache.", i)
		}

		//Test RemoveZone external
		c.RemoveZone("ch")
		if c.Len() != 0 {
			t.Errorf("%d:Was not able to remove elements of zone '.' from cache.", i)
		}
		//Test RemoveExpired from internal and external elements
		c.AddZone(zones[2], zones[2].ValidUntil(), true)
		c.AddShard(shards[4], shards[4].ValidUntil(), false)
		c.AddShard(shards[0], shards[0].ValidUntil(), false)
		c.RemoveExpiredValues()
		s, ok = c.Get(shards[0].SubjectZone, shards[0].Context, section.TotalInterval{})
		if c.Len() != 1 || s[0] != shards[0] {
			t.Errorf("%d:Was not able to remove correct expired elements from cache. len=%d", i, c.Len())
		}

	}
}

func TestNegAssertionCheckpoint(t *testing.T) {
	var tests = []struct {
		input Assertion
	}{
		{
			&AssertionImpl{
				cache:                  lruCache.New(),
				counter:                safeCounter.New(4),
				zoneMap:                safeHashMap.New(),
				entriesPerAssertionMap: make(map[string]int),
			},
		},
	}
	for i, test := range tests {
		delegationsCH := getExampleDelgations("ch")
		delegationsORG := getExampleDelgations("org")
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		//Add delegationAssertions
		c.Add(delegationsCH[0], time.Now().Add(time.Hour).Unix(), false)
		c.Add(delegationsORG[0], time.Now().Add(time.Hour).Unix(), false)
		//Test Checkpointing
		assertions := c.Checkpoint()
		if len(assertions) != 2 {
			t.Errorf("Number of assertions is wrong")
		}
		if !reflect.DeepEqual(assertions[0], delegationsCH[0]) && !reflect.DeepEqual(assertions[1], delegationsCH[0]) {
			t.Errorf("ch assertion not checkpointed")
		}
		if !reflect.DeepEqual(assertions[0], delegationsORG[0]) && !reflect.DeepEqual(assertions[1], delegationsORG[0]) {
			t.Errorf("org assertion not checkpointed")
		}
	}
}
