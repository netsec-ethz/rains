package cache

import (
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

func TestPendingKeyCache(t *testing.T) {
	mss, _ := getQueries()
	var tests = []struct {
		input PendingKey
	}{
		{&PendingKeyImpl{counter: safeCounter.New(4), tokenMap: safeHashMap.New()}},
	}
	for i, test := range tests {
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		//Test c.Add()
		c.Add(mss[0], mss[0].Token, time.Now().Add(time.Hour).Unix())
		if c.Len() != 1 {
			t.Error("mss[0] was not added to the cache")
		}
		c.Add(mss[1], mss[1].Token, time.Now().Add(time.Hour).Unix())
		if c.Len() != 2 {
			t.Error("mss[1] was not added to the cache")
		}
		c.Add(mss[2], mss[2].Token, time.Now().Add(time.Hour).Unix())
		if c.Len() != 3 {
			t.Error("mss[2] was not added to the cache")
		}
		//Test c.ContainsToken()
		if !c.ContainsToken(mss[0].Token) || !c.ContainsToken(mss[0].Token) ||
			!c.ContainsToken(mss[0].Token) || c.ContainsToken(token.New()) {
			t.Error("unexpected token was in the cache")
		}
		//Test c.GetAndRemove()
		if v, ok := c.GetAndRemove(mss[0].Token); !ok || c.Len() != 2 ||
			!reflect.DeepEqual(v, mss[0]) {
			t.Error("mss[0] should be returned for this token")
		}
		if v, ok := c.GetAndRemove(mss[1].Token); !ok || c.Len() != 1 ||
			!reflect.DeepEqual(v, mss[1]) {
			t.Error("mss[1] should be returned for this token")
		}
		if v, ok := c.GetAndRemove(mss[2].Token); !ok || c.Len() != 0 ||
			!reflect.DeepEqual(v, mss[2]) {
			t.Error("mss[2] should be returned for this token")
		}
		//Test c.RemoveExpiredValues()
		c.Add(mss[0], mss[0].Token, time.Now().Add(time.Hour).Unix())
		c.Add(mss[2], mss[2].Token, time.Now().Add(-time.Hour).Unix())
		c.RemoveExpiredValues()
		if v, ok := c.GetAndRemove(mss[0].Token); !ok || c.Len() != 0 ||
			!reflect.DeepEqual(v, mss[0]) {
			t.Error("expired value was not removed")
		}
	}
}

func TestPendingKeyCacheCounter(t *testing.T) {
	mss, _ := getQueries()
	var tests = []struct {
		maxSize int
	}{
		{2},
	}
	for _, test := range tests {
		c := &PendingKeyImpl{counter: safeCounter.New(test.maxSize), tokenMap: safeHashMap.New()}
		c.Add(mss[0], mss[0].Token, time.Now().Add(time.Hour).Unix())
		//Test same token
		c.Add(mss[1], mss[0].Token, time.Now().Add(time.Hour).Unix())
		if c.Len() != 1 {
			t.Error("entry added with same token did not overwrite old value")
		}
		c.Add(mss[1], mss[1].Token, time.Now().Add(time.Hour).Unix())
		//Test MaxSize
		c.Add(mss[2], mss[2].Token, time.Now().Add(time.Hour).Unix())
		if c.Len() != 2 {
			t.Error("was able to add more entries than maxSize")
		}
	}
}
