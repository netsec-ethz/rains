package cache

import (
	"testing"
)

//TODO make compatible with new pendingQueryCache
func TestPendingQueryCache(t *testing.T) {
	/*a0 := &section.Assertion{
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content:     []object.Object{object.Object{Type: object.OTIP4Addr, Value: "192.0.2.0"}},
	}
	a1 := &section.Assertion{
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content:     []object.Object{object.Object{Type: object.OTIP4Addr, Value: "203.0.113.0"}},
	}
	s0 := &section.Shard{SubjectZone: "net", RangeFrom: "e", RangeTo: "f"}
	q0 := &query.Name{Name: "example.net", Context: ".", Types: []object.Type{2}}
	q1 := &query.Name{Name: "example.com", Context: ".", Types: []object.Type{2}}
	m := []msgSectionSender{
		msgSectionSender{Section: q0, Sender: connection.Info{}, Token: token.New()},
		msgSectionSender{Section: q0, Sender: connection.Info{}, Token: token.New()},
		msgSectionSender{Section: q1, Sender: connection.Info{}, Token: token.New()},
	}
	tokens := []token.Token{token.New(), token.New(), token.New()}
	var tests = []struct {
		input pendingQueryCache
	}{
		{&pendingQueryCacheImpl{counter: safeCounter.New(4), tokenMap: safeHashMap.New(),
			nameCtxTypesMap: safeHashMap.New()},
		},
	}
	for i, test := range tests {
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		//Add: different query and same query,
		expectedValues := []bool{true, false, true}
		for j := 0; j < 3; j++ {
			sendQuery := c.Add(m[j])
			if c.Len() != j+1 {
				t.Errorf("%d.%d:section was not added to the cache. len=%d", i, j, c.Len())
			}
			if sendQuery != expectedValues[j] {
				t.Errorf("%d.%d:incorrect Add() return value. expected=%v actual=%v", i, j, expectedValues[j], sendQuery)
			}
		}
		//check that queries get dropped when the cache is full
		for j := 0; j < len(m); j++ {
			sendQuery := c.Add(m[j])
			if c.Len() != 3 {
				t.Errorf("%d.%d:query was added to the cache. len=%d", i, j, c.Len())
			}
			if sendQuery {
				t.Errorf("%d.%d:incorrect Add() return value. expected=false actual=%v", i, j, sendQuery)
			}
		}
		//Add token to cache entries
		ok := c.AddToken(token.New(), time.Now().Add(time.Second).Unix(),
			connection.Info{}, "example.com", ".", []object.Type{3})
		if ok {
			t.Errorf("%d:token added to non existing entry. len=%d", i, c.Len())
		}
		ok = c.AddToken(token.New(), time.Now().Add(time.Second).Unix(),
			connection.Info{}, "example.com", "nonExistingContext", []object.Type{2})
		if ok {
			t.Errorf("%d:token added to non existing entry. len=%d", i, c.Len())
		}
		ok = c.AddToken(token.New(), time.Now().Add(time.Second).Unix(),
			connection.Info{}, "nonExistingName", ".", []object.Type{2})
		if ok {
			t.Errorf("%d:token added to non existing entry. len=%d", i, c.Len())
		}
		ok = c.AddToken(tokens[0], time.Now().Add(time.Second).Unix(), connection.Info{}, q0.Name,
			q0.Context, q0.Types)
		if !ok {
			t.Errorf("%d:wrong return value of addToken()", i)
		}
		ok = c.AddToken(tokens[1], time.Now().Add(time.Second).Unix(), connection.Info{}, q1.Name,
			q1.Context, q1.Types)
		if !ok {
			t.Errorf("%d:wrong return value of addToken()", i)
		}
		//Get Query based on token
		query, ok := c.GetQuery(token.New())
		if ok {
			t.Errorf("%d.0:wrong return value of GetQuery() expected=[nil false] actual=[%v %v]", i, ok, query)
		}
		query, ok = c.GetQuery(tokens[0])
		if !ok || !reflect.DeepEqual(query, q0) {
			t.Errorf("%d.1:wrong return value of GetQuery() expected=[%v false] actual=[%v %v]", i, q0, ok, query)
		}
		query, ok = c.GetQuery(tokens[1])
		if !ok || !reflect.DeepEqual(query, q1) {
			t.Errorf("%d.2:wrong return value of GetQuery() expected=[%v false] actual=[%v %v]", i, q1, ok, query)
		}
		//Add answers to cache entries
		deadline := time.Now().Add(time.Second).UnixNano()
		ok = c.AddAnswerByToken(a0, token.New(), deadline)
		if ok {
			t.Errorf("%d.0:wrong return value of AddAnswerByToken() expected=false actual=%v", i, ok)
		}

		ok = c.AddAnswerByToken(a0, tokens[0], deadline)
		if !ok {
			t.Errorf("%d.1:wrong return value of AddAnswerByToken() ok=%v", i, ok)
		}
		ok = c.AddAnswerByToken(a0, tokens[0], deadline) //same entry
		if ok {
			t.Errorf("%d.2:wrong return value of AddAnswerByToken() ok=%v", i, ok)
		}
		ok = c.AddAnswerByToken(a1, tokens[0], deadline) //different entry
		if !ok {
			t.Errorf("%d.3:wrong return value of AddAnswerByToken() ok=%v", i, ok)
		}
		ok = c.AddAnswerByToken(s0, tokens[1], deadline) //non assertions also accepted
		if !ok {
			t.Errorf("%d.4:wrong return value of AddAnswerByToken() ok=%v", i, ok)
		}
		//Token update
		ok = c.UpdateToken(token.New(), token.New())
		if !ok {
			t.Errorf("%d.0:wrong return value of UpdateToken() ok=%v", i, ok)
		}
		ok = c.UpdateToken(tokens[0], tokens[1])
		if ok {
			t.Errorf("%d.1:wrong return value of UpdateToken() ok=%v", i, ok)
		}
		ok = c.UpdateToken(tokens[1], tokens[2])
		if !ok {
			t.Errorf("%d.2:wrong return value of UpdateToken() ok=%v", i, ok)
		}
		//Check removal by token and get correct responses.
		sectionSenders, answers := c.GetAndRemoveByToken(token.New(), deadline)
		if sectionSenders != nil || answers != nil {
			t.Errorf("%d.0:wrong return value of GetAndRemoveByToken() queries=%v answers=%v", i,
				sectionSenders, answers)
		}
		sectionSenders, answers = c.GetAndRemoveByToken(tokens[0], 0)
		if sectionSenders != nil || answers != nil {
			t.Errorf("%d.1:wrong return value of GetAndRemoveByToken() queries=%v answers=%v", i,
				sectionSenders, answers)
		}
		sectionSenders, answers = c.GetAndRemoveByToken(tokens[0], deadline)
		if len(sectionSenders) != 2 || !reflect.DeepEqual(sectionSenders, m[:2]) ||
			len(answers) != 2 || (answers[0] == a0 && answers[1] != a1 ||
			answers[0] == a1 && answers[1] != a0 || answers[0] != a0 && answers[0] != a1 ||
			c.Len() != 1) {
			t.Errorf("%d.2:wrong return value of GetAndRemoveByToken() queries=%v answers=%v", i,
				sectionSenders, answers)
		}
		sectionSenders, answers = c.GetAndRemoveByToken(tokens[2], deadline)
		if len(sectionSenders) != 1 || sectionSenders[0] != m[2] || len(answers) != 1 ||
			answers[0] != s0 || c.Len() != 0 {
			t.Errorf("%d.3:wrong return value of GetAndRemoveByToken() queries=%v answers=%v", i,
				sectionSenders, answers)
		}
		//resend after expiration
		sendQuery := c.Add(m[0])
		if c.Len() != 1 {
			t.Errorf("%d:was not able to add query to cache. len=%d", i, c.Len())
		}
		if !sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=true actual=%v", i, sendQuery)
		}
		time.Sleep(2 * time.Second)
		sendQuery = c.Add(m[0])
		if c.Len() != 2 {
			t.Errorf("%d:was not able to add query to cache. len=%d", i, c.Len())
		}
		if !sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=true actual=%v", i, sendQuery)
		}
		//remove expired entries
		time.Sleep(2 * time.Second)
		c.RemoveExpiredValues()
		if c.Len() != 0 {
			t.Errorf("%d:Expired value was not removed. len=%d", i, c.Len())
		}

	}*/
}
