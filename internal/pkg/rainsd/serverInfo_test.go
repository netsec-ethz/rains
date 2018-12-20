package rainsd

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"golang.org/x/crypto/ed25519"
)

func TestCapabilityCache(t *testing.T) {
	//TODO CFE remove these manually added entries once there is a working add implementation
	cache := lruCache.New()
	cache.GetOrAdd("e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745",
		[]message.Capability{message.TLSOverTCP}, true)
	cache.GetOrAdd("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71",
		[]message.Capability{message.NoCapability}, false)
	counter := safeCounter.New(10)
	counter.Add(2)
	var tests = []struct {
		input capabilityCache
	}{
		{&capabilityCacheImpl{capabilityMap: cache, counter: counter}},
	}
	for i, test := range tests {
		c := test.input
		if c.Len() != 2 {
			t.Error("init size is incorrect", "size", c.Len())
		}
		//TODO CFE test add when it is correctly implemented.
		caps, ok := c.Get([]byte("e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745"))
		if !ok {
			t.Errorf("%d: Get did not returned contained element.", i)
		}
		if !reflect.DeepEqual(caps, []message.Capability{message.TLSOverTCP}) {
			t.Errorf("%d: Returned element is wrong", i)
		}
		caps, ok = c.Get([]byte("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71"))
		if !ok {
			t.Errorf("%d: Get did not returned contained element.", i)
		}
		if !reflect.DeepEqual(caps, []message.Capability{message.NoCapability}) {
			t.Errorf("%d: Returned element is wrong", i)
		}
	}
}

func TestConnectionCache(t *testing.T) {
	var tests = []struct {
		input connectionCache
	}{
		{&connectionCacheImpl{cache: lruCache.New(), counter: safeCounter.New(3)}},
	}
	for i, test := range tests {
		tcpAddr := "localhost:8000"
		tcpAddr2 := "localhost:8001"
		tcpAddr3 := "localhost:8002"
		go mockServer(tcpAddr, t)
		go mockServer(tcpAddr2, t)
		go mockServer(tcpAddr3, t)
		time.Sleep(time.Millisecond * 50)
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		conn1, _ := net.Dial("tcp", tcpAddr)
		conn2, _ := net.Dial("tcp", tcpAddr2)
		conn3, _ := net.Dial("tcp", tcpAddr3)
		connInfo1 := connection.Info{Type: connection.TCP, TCPAddr: conn1.RemoteAddr().(*net.TCPAddr)}
		connInfo2 := connection.Info{Type: connection.TCP, TCPAddr: conn2.RemoteAddr().(*net.TCPAddr)}
		connInfo3 := connection.Info{Type: connection.TCP, TCPAddr: conn3.RemoteAddr().(*net.TCPAddr)}
		c.AddConnection(conn1)
		c.AddConnection(conn2)
		if c.Len() != 2 {
			t.Errorf("%d: size is incorrect after 2 inserts. actual=%d", i, c.Len())
		}
		c.AddConnection(conn3)
		//Check that lru is working
		if c.Len() != 2 {
			t.Errorf("%d: size is incorrect after lru removal expected=2 actual=%d", i, c.Len())
		}
		_, ok := c.GetConnection(connInfo1)
		if ok {
			t.Errorf("%d: Wrong connection removed", i)
		}
		outConn2, ok := c.GetConnection(connInfo2)
		if !ok {
			t.Errorf("%d: Wrong connection removed", i)
		}
		_, ok = c.GetConnection(connInfo3)
		if !ok {
			t.Errorf("%d: Wrong connection removed", i)
		}
		//test that connection can still be used.
		outConn2[0].Write([]byte("testMsg\n"))
		buffer := make([]byte, 7)
		_, err := outConn2[0].Read(buffer)
		if err != nil || !reflect.DeepEqual(buffer, []byte("testMsg")) {
			t.Errorf("%d: Connection is not active or msg received is wrong", i)
		}
		//test adding capability
		capabilityList := []message.Capability{message.TLSOverTCP}
		ok = c.AddCapabilityList(connInfo2, capabilityList)
		if !ok {
			t.Errorf("%d: Was not able to add capability list to connection2", i)
		}
		ok = c.AddCapabilityList(connInfo1, capabilityList)
		if ok {
			t.Errorf("%d: Was able to add capability list to connection1 although it is not in the cache", i)
		}
		//test retrieving capability
		returnList, ok := c.GetCapabilityList(connInfo2)
		if !ok || !reflect.DeepEqual(returnList, capabilityList) {
			t.Errorf("%d: Obtained capability list does not matched added one or was not found", i)
		}
		returnList, ok = c.GetCapabilityList(connInfo1)
		if ok || returnList != nil {
			t.Errorf("%d: Nothing should have been returned", i)
		}
		//test closeAndRemoveConnection
		c.CloseAndRemoveConnection(conn2)
		_, ok = c.GetConnection(connInfo2)
		if ok || c.Len() != 1 {
			t.Errorf("%d: Wrong connection removed or count is off", i)
		}
	}
}

func mockServer(tcpAddr string, t *testing.T) {
	ln, _ := net.Listen("tcp", tcpAddr)
	for {
		conn, _ := ln.Accept()
		go handleConn(conn)
	}
}

//handleConn responds with the same message as received
func handleConn(c net.Conn) {
	input := bufio.NewScanner(c)
	for input.Scan() {
		c.Write([]byte(input.Text()))
	}
	c.Close()
}

//FIXME CFE we cannot test if the cache logs correctly when the maximum number of delegations per
//zone is reached. Should we return a value if so in which form (object, error)?
func TestZoneKeyCache(t *testing.T) {
	var tests = []struct {
		input zonePublicKeyCache
	}{
		//Warn when there are 4 entries in the cache. Replace one/some if there is a 5th added.
		{&zoneKeyCacheImpl{cache: lruCache.New(), counter: safeCounter.New(5), warnSize: 4,
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

//FIXME CFE we cannot test if the cache logs correctly when the maximum number of delegations per
//zone is reached. Should we return a value if so in which form (object, error)?
func TestPendingKeyCache(t *testing.T) {
	a0 := &section.Assertion{SubjectZone: "com", Context: "."}
	s1 := &section.Shard{SubjectZone: "com", Context: "."}
	z2 := &section.Zone{SubjectZone: "ch", Context: "."}
	a3 := &section.Assertion{SubjectZone: "ch", Context: "."}
	m := []sectionWithSigSender{
		sectionWithSigSender{Section: a0, Sender: connection.Info{}, Token: token.New()},
		sectionWithSigSender{Section: s1, Sender: connection.Info{}, Token: token.New()},
		sectionWithSigSender{Section: z2, Sender: connection.Info{}, Token: token.New()},
		sectionWithSigSender{Section: a3, Sender: connection.Info{}, Token: token.New()},
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
	}
}

func TestPendingQueryCache(t *testing.T) {
	a0 := &section.Assertion{
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

	}
}

func TestAssertionCache(t *testing.T) {
	var tests = []struct {
		input assertionCache
	}{
		//Warn when there are 4 entries in the cache. Replace one/some if there is a 5th added.
		{
			&assertionCacheImpl{
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

func TestNegAssertionCache(t *testing.T) {

	var tests = []struct {
		input negativeAssertionCache
	}{
		//Warn when there are 4 entries in the cache. Replace one/some if there is a 5th added.
		{
			&negativeAssertionCacheImpl{
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
			t.Errorf("%d:Was not able to remove correct expired elements from cache.", i)
		}
	}
}

func TestNameCtxTypesKey(t *testing.T) {
	var tests = []struct {
		name    string
		context string
		types   []object.Type
		output  string
	}{
		{"example.com", ".", nil, "example.com . nil"},
		{"example.com", ".", []object.Type{5, 8, 1, 6}, "example.com . [1 5 6 8]"},
	}
	for i, test := range tests {
		if nameCtxTypesKey(test.name, test.context, test.types) != test.output {
			t.Errorf("%d:Wrong return value expected=%s actual=%s", i, test.output,
				nameCtxTypesKey(test.name, test.context, test.types))
		}
	}
}

func TestZoneCtxKey(t *testing.T) {
	var tests = []struct {
		zone    string
		context string
		output  string
	}{
		{"", "", " "},
		{"example.com", ".", "example.com ."},
	}
	for i, test := range tests {
		if zoneCtxKey(test.zone, test.context) != test.output {
			t.Errorf("%d:Wrong return value expected=%s actual=%s", i, test.output,
				zoneCtxKey(test.zone, test.context))
		}
	}
}

func TestAlgoPhaseKey(t *testing.T) {
	var tests = []struct {
		algoType algorithmTypes.Signature
		phase    int
		output   string
	}{
		{algorithmTypes.Ed25519, 2, "1 2"},
	}
	for i, test := range tests {
		if algoPhaseKey(test.algoType, test.phase) != test.output {
			t.Errorf("%d:Wrong return value expected=%s actual=%s", i, test.output,
				algoPhaseKey(test.algoType, test.phase))
		}
	}
}

func TestSectionWithSigSenderHash(t *testing.T) {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "192.0.2.0:80")
	token := token.New()
	var tests = []struct {
		input  sectionWithSigSender
		output string
	}{
		{
			sectionWithSigSender{
				Section: &section.Assertion{SubjectName: "name", SubjectZone: "zone", Context: "context"},
				Sender:  connection.Info{Type: connection.TCP, TCPAddr: tcpAddr},
				Token:   token,
			},
			fmt.Sprintf("1_192.0.2.0:80_A_name_zone_context_[]_[]_%s", hex.EncodeToString(token[:])),
		},
	}
	for i, test := range tests {
		if test.input.Hash() != test.output {
			t.Errorf("%d:Wrong return value expected=%s actual=%s", i, test.output,
				test.input.Hash())
		}
	}
}

func getExampleDelgations(tld string) []*section.Assertion {
	a1 := &section.Assertion{
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a2 := &section.Assertion{ //same key phase as a1 but different key and validity period
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Add(25 * time.Hour).Unix(),
					ValidUntil:  time.Now().Add(48 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey2")),
				},
			},
		},
	}
	a3 := &section.Assertion{ //different keyphase, everything else the same as a1
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 1},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	//expired delegation assertion
	a4 := &section.Assertion{ //different keyphase, everything else the same as a1
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 1},
					ValidSince:  time.Now().Add(-2 * time.Hour).Unix(),
					ValidUntil:  time.Now().Add(-1 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a5 := &section.Assertion{ //different keyphase, everything else the same as a1
		SubjectName: "@",
		SubjectZone: ".",
		Context:     ".",
		Content: []object.Object{
			object.Object{
				Type: object.OTDelegation,
				Value: keys.PublicKey{
					PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a1.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	a2.UpdateValidity(time.Now().Unix(), time.Now().Add(48*time.Hour).Unix(), 48*time.Hour)
	a3.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	a4.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	a5.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	return []*section.Assertion{a1, a2, a3, a4, a5}
}

func getSignatureMetaData() []signature.MetaData {
	//signature in the interval of the above public keys
	s1 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(23 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
	}
	s2 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
		ValidUntil:  time.Now().Add(30 * time.Hour).Unix(),
	}
	s3 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 1},
		ValidSince:  time.Now().Add(23 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
	}
	//signature not in the interval of the above public keys
	s4 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(-2 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(-1 * time.Hour).Unix(),
	}
	s5 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(48*time.Hour + 1).Unix(),
		ValidUntil:  time.Now().Add(50 * time.Hour).Unix(),
	}
	s6 := signature.MetaData{
		PublicKeyID: keys.PublicKeyID{Algorithm: algorithmTypes.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(24*time.Hour + 1).Unix(),
		ValidUntil:  time.Now().Add(25*time.Hour - 1).Unix(),
	}

	return []signature.MetaData{s1, s2, s3, s4, s5, s6}
}

func getAssertions() []*section.Assertion {
	s0 := &section.Assertion{
		SubjectName: "b",
		SubjectZone: "ch",
		Context:     ".",
	}
	s1 := &section.Assertion{
		SubjectName: "e",
		SubjectZone: "ch",
		Context:     ".",
	}
	s2 := &section.Assertion{
		SubjectName: "a",
		SubjectZone: "org",
		Context:     ".",
	}
	s3 := &section.Assertion{
		SubjectName: "b",
		SubjectZone: "org",
		Context:     "test-cch",
	}
	return []*section.Assertion{s0, s1, s2, s3}
}

func getShards() []*section.Shard {
	s0 := &section.Shard{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "a",
		RangeTo:     "c",
	}
	s1 := &section.Shard{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "a",
		RangeTo:     "b",
	}
	s2 := &section.Shard{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "c",
		RangeTo:     "f",
	}
	s3 := &section.Shard{
		SubjectZone: "org",
		Context:     ".",
		RangeFrom:   "c",
		RangeTo:     "z",
	}
	s4 := &section.Shard{
		SubjectZone: "net",
		Context:     ".",
		RangeFrom:   "s",
		RangeTo:     "v",
	}
	s0.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	s1.UpdateValidity(time.Now().Unix(), time.Now().Add(48*time.Hour).Unix(), 48*time.Hour)
	s2.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	s3.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	s4.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	return []*section.Shard{s0, s1, s2, s3, s4}
}

func getZones() []*section.Zone {
	s0 := &section.Zone{
		SubjectZone: "ch",
		Context:     ".",
	}
	s1 := &section.Zone{
		SubjectZone: "org",
		Context:     ".",
	}
	s2 := &section.Zone{
		SubjectZone: "org",
		Context:     "test-cch",
	}
	s0.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	s1.UpdateValidity(time.Now().Unix(), time.Now().Add(48*time.Hour).Unix(), 48*time.Hour)
	s2.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	return []*section.Zone{s0, s1, s2}
}
