package cache

import (
	"fmt"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/object"
)

func TestAssertionCache(t *testing.T) {
	var tests = []struct {
		input Assertion
	}{
		//Warn when there are 4 entries in the cache. Replace one/some if there is a 5th added.
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
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		assertions := getExampleDelgations("ch") //used when isAuthoritative=false
		aORG := getExampleDelgations("org")      //used when isAuthoritative=true
		//Test add
		if ok := c.Add(aORG[0], aORG[0].ValidUntil(), true); !ok || c.Len() != 1 {
			t.Errorf("%d:Assertion was not added to cache. expected=%d actual=%d", i, 1, c.Len())
		}

		if ok := c.Add(assertions[0], assertions[0].ValidUntil(), false); !ok || c.Len() != 2 {
			t.Errorf("%d:Assertion was not added to cache. expected=%d actual=%d", i, 2, c.Len())
		}

		if ok := c.Add(assertions[1], assertions[1].ValidUntil(), false); !ok || c.Len() != 3 {
			t.Errorf("%d:Assertion was not added to cache. expected=%d actual=%d", i, 3, c.Len())
		}

		if ok := c.Add(assertions[2], assertions[2].ValidUntil(), false); ok || c.Len() != 1 {
			//All external assertions are removed because they have the same name, zone, ctx and type
			t.Errorf("%d:Assertion was not added to cache. expected=%d actual=%d", i, 1, c.Len())
		}
		c.Add(assertions[0], assertions[0].ValidUntil(), false)
		//Test Get
		//external element
		a, ok := c.Get(fmt.Sprintf("%s%s", assertions[0].SubjectName, assertions[0].SubjectZone), assertions[0].Context,
			assertions[0].Content[0].Type, false)
		if !ok || len(a) != 1 || assertions[0] != a[0] {
			t.Errorf("%d:Was not able to get correct assertion from cache expected=%s actual=%s", i, assertions[0], a[0])
		}
		//internal element
		a, ok = c.Get(fmt.Sprintf("%s%s", aORG[0].SubjectName, aORG[0].SubjectZone), aORG[0].Context,
			aORG[0].Content[0].Type, false)
		if !ok || len(a) != 1 || aORG[0] != a[0] {
			t.Errorf("%d:Was not able to get correct assertion from cache expected=%s actual=%s", i, aORG[0], a[0])
		}
		//more than one answer
		c.Add(assertions[1], assertions[1].ValidUntil(), false)
		a, ok = c.Get(fmt.Sprintf("%s%s", assertions[0].SubjectName, assertions[0].SubjectZone), assertions[0].Context,
			assertions[0].Content[0].Type, false)
		if !ok || len(a) != 2 || (a[0] == assertions[0] && a[1] != assertions[1]) ||
			(a[0] == assertions[1] && a[1] != assertions[0]) || (a[0] == assertions[0] && a[0] == assertions[1]) {
			t.Errorf("%d:Was not able to get correct assertion from cache expected=%s actual=%s", i, assertions, a)
		}
		//Test Add with multiple objects
		aORG[1].Content = append(aORG[1].Content, object.Object{Type: object.OTIP4Addr, Value: "192.0.2.0"})
		if ok := c.Add(aORG[1], aORG[1].ValidUntil(), true); ok || c.Len() != 3 {
			//All external assertions are removed because they have the same name, zone, ctx and type
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}
		//Test RemoveZone
		c.RemoveZone(".")
		if c.Len() != 0 {
			t.Errorf("%d:Was not able to remove elements of zone '.' from cache.", i)
		}

		//remove from internal and external
		c.Add(aORG[0], aORG[0].ValidUntil(), true)
		c.Add(assertions[1], assertions[1].ValidUntil(), false)
		c.RemoveZone(".")
		if c.Len() != 0 {
			t.Errorf("%d:Was not able to remove elements of zone '.' from cache.", i)
		}

		//other zones are not affected
		assertions[2].SubjectZone = "com"
		c.Add(aORG[0], aORG[0].ValidUntil(), true)
		c.Add(assertions[2], assertions[2].ValidUntil(), false)
		c.RemoveZone("com")
		a, ok = c.Get(fmt.Sprintf("%s%s", aORG[0].SubjectName, aORG[0].SubjectZone), aORG[0].Context,
			aORG[0].Content[0].Type, false)
		if c.Len() != 1 || a[0] != aORG[0] {
			t.Errorf("%d:Was not able to remove correct elements of zone '.' from cache.", i)
		}

		//Test RemoveExpired for internal and external elements
		c.Add(aORG[3], aORG[3].ValidUntil(), true)
		c.Add(assertions[3], assertions[3].ValidUntil(), false)

		c.RemoveExpiredValues()
		a, ok = c.Get(fmt.Sprintf("%s%s", aORG[0].SubjectName, aORG[0].SubjectZone), aORG[0].Context,
			aORG[0].Content[0].Type, false)
		if c.Len() != 1 || a[0] != aORG[0] {
			t.Errorf("%d:Was not able to remove correct expired elements from cache.", i)
		}

	}
}
