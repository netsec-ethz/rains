package cache

import (
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//TODO make compatible with new pendingQueryCache
func TestPendingQueryCache(t *testing.T) {
	mss, _ := getQueries()
	var tests = []struct {
		maxSize int
	}{
		{3},
	}
	for i, test := range tests {
		c := &PendingQueryImpl{counter: safeCounter.New(test.maxSize),
			tokenMap: make(map[token.Token]*pqcValue), queryMap: make(map[string]token.Token)}
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		//Test c.Add()
		if ok := c.Add(mss[0], mss[0].Token, time.Now().Add(time.Hour).Unix()); !ok || c.Len() != 1 {
			t.Error("mss[0] was not added to the cache")
		}
		if ok := c.Add(mss[1], mss[1].Token, time.Now().Add(time.Hour).Unix()); ok || c.Len() != 2 {
			t.Error("mss[1] was not added to the cache")
		}
		if ok := c.Add(mss[2], mss[2].Token, time.Now().Add(time.Hour).Unix()); !ok || c.Len() != 3 {
			t.Error("mss[2] was not added to the cache")
		}
		//Test c.GetAndRemove()
		if v := c.GetAndRemove(mss[1].Token); len(v) != 0 || c.Len() != 3 {
			t.Error("token should not be part of the cache")
		}
		if v := c.GetAndRemove(mss[2].Token); len(v) != 1 || !reflect.DeepEqual(v[0], mss[2]) ||
			c.Len() != 2 {
			t.Error("mss[2] should be returned for this token")
		}
		if v := c.GetAndRemove(mss[0].Token); len(v) != 2 || !reflect.DeepEqual(v[0], mss[0]) ||
			!reflect.DeepEqual(v[1], mss[1]) || c.Len() != 0 {
			t.Error("mss[0] and mss[1] should be returned for this token")
		}
		//Test c.RemoveExpiredValues()
		c.Add(mss[0], mss[0].Token, time.Now().Add(time.Hour).Unix())
		c.Add(mss[2], mss[2].Token, time.Now().Add(-time.Hour).Unix())
		c.RemoveExpiredValues()
		if v := c.GetAndRemove(mss[0].Token); c.Len() != 0 || !reflect.DeepEqual(v[0], mss[0]) {
			t.Error("expired value was not removed")
		}

		//Add and retrieve delegation query
		if ok := c.Add(mss[3], mss[3].Token, time.Now().Add(time.Hour).Unix()); !ok || c.Len() != 1 {
			t.Error("mss[0] was not added to the cache")
		}
		if v := c.GetAndRemove(mss[3].Token); len(v) != 1 || !reflect.DeepEqual(v[0], mss[3]) ||
			c.Len() != 0 {
			t.Error("mss[3] was not added to the cache")
		}

		//Add invalid input
		invalidMss := mss[0]
		invalidMss.Sections = []section.Section{&section.Assertion{}}
		if ok := c.Add(invalidMss, invalidMss.Token, time.Now().Add(time.Hour).Unix()); ok || c.Len() != 0 {
			t.Error("mss with non query section was added to the cache")
		}

		//Test test maxSize
		for j := 0; j < test.maxSize; j++ {
			c.Add(mss[0], token.New(), time.Now().Add(time.Hour).Unix())
		}
		c.Add(mss[0], token.New(), time.Now().Add(time.Hour).Unix())
		if c.Len() != test.maxSize {
			t.Error("was able to add more entries than maxSize")
		}
	}
}
