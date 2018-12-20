package cache

import (
	"testing"
)

//TODO make compatible with new pendingKeyCache
func TestPendingKeyCache(t *testing.T) {
	/*a0 := &section.Assertion{SubjectZone: "com", Context: "."}
	s1 := &section.Shard{SubjectZone: "com", Context: "."}
	z2 := &section.Zone{SubjectZone: "ch", Context: "."}
	a3 := &section.Assertion{SubjectZone: "ch", Context: "."}
	m := []util.SectionWithSigSender{
		util.SectionWithSigSender{Section: a0, Sender: connection.Info{}, Token: token.New()},
		util.SectionWithSigSender{Section: s1, Sender: connection.Info{}, Token: token.New()},
		util.SectionWithSigSender{Section: z2, Sender: connection.Info{}, Token: token.New()},
		util.SectionWithSigSender{Section: a3, Sender: connection.Info{}, Token: token.New()},
	}
	tokens := []token.Token{token.New(), token.New()}
	var tests = []struct {
		input pendingKeyCache
	}{
		{&pendingKeyCacheImpl{counter: safeCounter.New(4), tokenMap: safeHashMap.New(),
			zoneCtxMap: safeHashMap.New()},
		},
	}
	for i, test := range tests {
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		//Add: different cacheValues and same cacheValue, same Algo, different Hash
		expectedValues := []bool{true, false, true}
		for j := 0; j < 3; j++ {
			sendQuery := c.Add(m[j], algorithmTypes.Ed25519, 1)
			if c.Len() != j+1 {
				t.Errorf("%d.%d:section was not added to the cache. len=%d", i, j, c.Len())
			}
			if sendQuery != expectedValues[j] {
				t.Errorf("%d.%d:incorrect Add() return value. expected=%v actual=%v", i, j, expectedValues[j], sendQuery)
			}
		}
		//check that no matter what the new section is, it gets dropped in case the cache is full
		for j := 0; j < len(m); j++ {
			sendQuery := c.Add(m[j], algorithmTypes.Ed25519, 1)
			if c.Len() != 3 {
				t.Errorf("%d.%d:section was added to the cache. len=%d", i, j, c.Len())
			}
			if sendQuery {
				t.Errorf("%d.%d:incorrect Add() return value. expected=false actual=%v", i, j, sendQuery)
			}
		}
		//Add token to cache entries
		ok := c.AddToken(token.New(), time.Now().Add(time.Second).Unix(), connection.Info{}, "de", ".")
		if ok {
			t.Errorf("%d:token added to non existing entry. len=%d", i, c.Len())
		}
		ok = c.AddToken(tokens[0], time.Now().Add(time.Second).Unix(), connection.Info{}, "com", ".")
		if !ok {
			t.Errorf("%d:wrong return value of addToken()", i)
		}
		ok = c.AddToken(tokens[1], time.Now().Add(time.Second).Unix(), connection.Info{}, "ch", ".")
		if !ok {
			t.Errorf("%d:wrong return value of addToken()", i)
		}
		//Check if token in cache
		newToken := token.New()
		if c.ContainsToken(newToken) {
			t.Errorf("%d:wrong return value of ContainsToken() actual=%v", i, newToken)
		}
		if !c.ContainsToken(tokens[0]) {
			t.Errorf("%d:wrong return value of ContainsToken() actual=%v", i, c.ContainsToken(tokens[0]))
		}
		if !c.ContainsToken(tokens[1]) {
			t.Errorf("%d:wrong return value of ContainsToken() actual=%v", i, c.ContainsToken(tokens[1]))
		}
		//Check removal by token
		v := c.GetAndRemoveByToken(token.New())
		if v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non matching token. len=%d", i, c.Len())
		}
		v = c.GetAndRemoveByToken(tokens[0])
		if c.Len() != 1 || len(v) != 2 || (v[0] == m[0] && v[1] != m[1] || v[0] == m[1] && v[1] != m[0] || v[0] != m[0] && v[0] != m[1]) {
			t.Errorf(`%d:Token was not added to correct cacheValue by AddToken() or
			incorrect entries are removed from cache. len=%d returnValue=%v`, i, c.Len(), v)
		}
		//Check remaining Add() cases: same cacheValue and different algo type or phase;
		//same cacheValue, same algo, same hash
		sendQuery := c.Add(m[3], algorithmTypes.Ed25519, 1) //different algo type
		if c.Len() != 2 {
			t.Errorf("%d:section was not added to the cache. len=%d", i, c.Len())
		}
		if sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=false actual=%v", i, sendQuery)
		}
		sendQuery = c.Add(m[3], algorithmTypes.Ed25519, 1) //duplicate
		if c.Len() != 2 {
			t.Errorf("%d:same section was added again to the cache. len=%d", i, c.Len())
		}
		if sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=false actual=%v", i, sendQuery)
		}
		sendQuery = c.Add(m[3], algorithmTypes.Ed25519, 0) //different phase
		if c.Len() != 3 {
			t.Errorf("%d:section was not added to the cache. len=%d", i, c.Len())
		}
		if sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=false actual=%v", i, sendQuery)
		}
		//Check GetAndRemove()
		//non existing elements
		v = c.GetAndRemove("none contained zone", ".", algorithmTypes.Ed25519, 0)
		if v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		v = c.GetAndRemove("ch", "non contained context", algorithmTypes.Ed25519, 0)
		if v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		v = c.GetAndRemove("ch", ".", algorithmTypes.Ed25519, 0)
		if v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		v = c.GetAndRemove("ch", ".", algorithmTypes.Ed25519, 2)
		if v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		//actual remove
		v = c.GetAndRemove("ch", ".", algorithmTypes.Ed25519, 1)
		if c.Len() != 2 || len(v) != 1 || v[0] != m[3] {
			t.Errorf("%d:GetAndRemove() wrong return values. len=%d expectedValue= %v returnValue=%v", i, c.Len(), m[3], v[0])
		}
		v = c.GetAndRemove("ch", ".", algorithmTypes.Ed25519, 0)
		if c.Len() != 1 || len(v) != 1 || v[0] != m[3] {
			t.Errorf("%d:GetAndRemove() wrong return values. len=%d expectedValue= %v returnValue=%v", i, c.Len(), m[3], v[0])
		}
		v = c.GetAndRemove("ch", ".", algorithmTypes.Ed25519, 1)
		if c.Len() != 0 || len(v) != 1 || v[0] != m[2] {
			t.Errorf("%d:GetAndRemove() wrong return values. len=%d expectedValue= %v returnValue=%v", i, c.Len(), m[2], v[0])
		}
		//correct cleanup of hash map keys
		sendQuery = c.Add(m[0], algorithmTypes.Ed25519, 0)
		if c.Len() != 1 {
			t.Errorf("%d:section was not added to the cache. len=%d", i, c.Len())
		}
		if !sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=true actual=%v", i, sendQuery)
		}
		ok = c.AddToken(tokens[0], time.Now().Unix(), connection.Info{}, "com", ".")
		if !ok {
			t.Errorf("%d:wrong return value of addToken().", i)
		}
		time.Sleep(2 * time.Second)
		//resend after expiration
		sendQuery = c.Add(m[0], algorithmTypes.Ed25519, 0)
		if c.Len() != 1 {
			t.Errorf("%d:same section was added again to the cache. len=%d", i, c.Len())
		}
		if !sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=true actual=%v", i, sendQuery)
		}
		time.Sleep(2 * time.Second)
		c.RemoveExpiredValues()
		if c.Len() != 0 {
			t.Errorf("%d:Expired value was not removed. len=%d", i, c.Len())
		}
	}*/
}
