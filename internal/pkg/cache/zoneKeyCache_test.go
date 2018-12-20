package cache

import (
	"reflect"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
)

func TestZoneKeyCache(t *testing.T) {
	var tests = []struct {
		input ZonePublicKey
	}{
		//Warn when there are 4 entries in the cache. Replace one/some if there is a 5th added.
		{&ZoneKeyImpl{cache: lruCache.New(), counter: safeCounter.New(5), warnSize: 4,
			maxPublicKeysPerZone: 2, keysPerContextZone: make(map[string]int)},
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
		for j := 0; j < 3; j++ {
			ok := c.Add(delegationsCH[j], delegationsCH[j].Content[0].Value.(keys.PublicKey), false)
			if c.Len() != j+1 {
				t.Errorf("%d:Delegation was not added to cache expected=%d actual=%d", i, j, c.Len())
			}
			if !ok {
				t.Errorf("%d:Wrong return value expected=true actual=%v", i, ok)
			}
		}
		ok := c.Add(delegationsORG[0], delegationsORG[0].Content[0].Value.(keys.PublicKey), false)
		if c.Len() != 4 {
			t.Errorf("%d:Delegation was not added to cache expected=%d actual=%d", i, 4, c.Len())
		}
		if ok {
			t.Errorf("%d:Wrong return value expected=false actual=%v", i, ok)
		}
		//Obtain previously added public keys
		signatures := getSignatureMetaData()
		for j := 0; j < 3; j++ {
			pkey, a, ok := c.Get("ch", ".", signatures[j])
			if !ok || pkey.CompareTo(delegationsCH[j].Content[0].Value.(keys.PublicKey)) != 0 ||
				!reflect.DeepEqual(a, delegationsCH[j]) {
				t.Errorf("%d:Get returned unexpected value actual=(%v,%v)", i, pkey, ok)
			}
		}
		pkey, a, ok := c.Get("org", ".", signatures[0])
		if !ok || pkey.CompareTo(delegationsORG[0].Content[0].Value.(keys.PublicKey)) != 0 ||
			!reflect.DeepEqual(a, delegationsORG[0]) {
			t.Errorf("%d:Get returned unexpected value actual=(%v,%v)", i, pkey, ok)
		}
		for j := 3; j < 3; j++ {
			pkey, a, ok = c.Get("ch", ".", signatures[j])
			if ok || pkey.CompareTo(keys.PublicKey{}) != 0 || a != nil {
				t.Errorf("%d:Get should not return public key actual=(%v,%v)", i, pkey, ok)
			}
		}
		//lru removal
		ok = c.Add(delegationsORG[1], delegationsORG[1].Content[0].Value.(keys.PublicKey), false)
		if c.Len() != 3 {
			t.Errorf("%d:lru removal deleted not enough keys expected=%d actual=%d", i, 2, c.Len())
		}
		if ok {
			t.Errorf("%d:Wrong return value expected=false actual=%v", i, ok)
		}
		_, _, ok = c.Get("ch", ".", signatures[0])
		if ok {
			t.Errorf("%d:Wrong entries where removed", i)
		}
		//Removal of expired keys
		c.Add(delegationsCH[3], delegationsCH[3].Content[0].Value.(keys.PublicKey), false)
		if c.Len() != 4 {
			t.Errorf("%d:Was not able to add expired delegation. expected=%d actual=%d", i, 3, c.Len())
		}
		c.RemoveExpiredKeys()
		if c.Len() != 3 {
			t.Errorf("%d:Was not able to remove expired delegation. expected=%d actual=%d", i, 2, c.Len())
		}
		//Test selfsigned root delegation
		ok = c.Add(delegationsORG[4], delegationsORG[4].Content[0].Value.(keys.PublicKey), false)
		if c.Len() != 4 {
			t.Errorf("%d:Delegation was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}
		pkey, a, ok = c.Get(".", ".", signatures[0])
		if !ok || pkey.CompareTo(delegationsORG[4].Content[0].Value.(keys.PublicKey)) != 0 ||
			!reflect.DeepEqual(a, delegationsORG[4]) {
			t.Errorf("%d:Get returned unexpected value actual=(%v,%v)", i, pkey, ok)
		}
	}
}
