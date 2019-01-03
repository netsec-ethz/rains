package cache

import (
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//TODO make compatible with new pendingQueryCache
func TestPendingQueryCache(t *testing.T) {
	mss, _ := getQueries()
	var tests = []struct {
		input PendingQuery
	}{
		{&PendingQueryImpl{counter: safeCounter.New(4), tokenMap: make(map[token.Token]*pqcValue),
			queryMap: make(map[string]token.Token)},
		},
	}
	for i, test := range tests {
		c := test.input
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
	}
}
