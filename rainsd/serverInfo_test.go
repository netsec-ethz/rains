package rainsd

import (
	"bufio"
	"net"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/lruCache"
	"github.com/netsec-ethz/rains/utils/safeCounter"
	"github.com/netsec-ethz/rains/utils/safeHashMap"
)

func TestCapabilityCache(t *testing.T) {
	//TODO CFE remove these manually added entries once there is a working add implementation
	cache := lruCache.New()
	cache.GetOrAdd("e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745",
		&[]rainslib.Capability{rainslib.TLSOverTCP}, true)
	cache.GetOrAdd("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71",
		&[]rainslib.Capability{rainslib.NoCapability}, false)
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
		if !reflect.DeepEqual(*caps, []rainslib.Capability{rainslib.TLSOverTCP}) {
			t.Errorf("%d: Returned element is wrong", i)
		}
		caps, ok = c.Get([]byte("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71"))
		if !ok {
			t.Errorf("%d: Get did not returned contained element.", i)
		}
		if !reflect.DeepEqual(*caps, []rainslib.Capability{rainslib.NoCapability}) {
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
		connInfo1 := rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: conn1.RemoteAddr().(*net.TCPAddr)}
		connInfo2 := rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: conn2.RemoteAddr().(*net.TCPAddr)}
		connInfo3 := rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: conn3.RemoteAddr().(*net.TCPAddr)}
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
		capabilityList := []rainslib.Capability{rainslib.TLSOverTCP}
		ok = c.AddCapabilityList(connInfo2, &capabilityList)
		if !ok {
			t.Errorf("%d: Was not able to add capability list to connection2", i)
		}
		ok = c.AddCapabilityList(connInfo1, &capabilityList)
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
			ok := c.Add(delegationsCH[j], delegationsCH[j].Content[0].Value.(rainslib.PublicKey), false)
			if c.Len() != j+1 {
				t.Errorf("%d:Delegation was not added to cache expected=%d actual=%d", i, j, c.Len())
			}
			if !ok {
				t.Errorf("%d:Wrong return value expected=true actual=%v", i, ok)
			}
		}
		ok := c.Add(delegationsORG[0], delegationsORG[0].Content[0].Value.(rainslib.PublicKey), false)
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
			if !ok || pkey.CompareTo(delegationsCH[j].Content[0].Value.(rainslib.PublicKey)) != 0 ||
				!reflect.DeepEqual(a, delegationsCH[j]) {
				t.Errorf("%d:Get returned unexpected value actual=(%v,%v)", i, pkey, ok)
			}
		}
		pkey, a, ok := c.Get("org", ".", signatures[0])
		if !ok || pkey.CompareTo(delegationsORG[0].Content[0].Value.(rainslib.PublicKey)) != 0 ||
			!reflect.DeepEqual(a, delegationsORG[0]) {
			t.Errorf("%d:Get returned unexpected value actual=(%v,%v)", i, pkey, ok)
		}
		for j := 3; j < 3; j++ {
			pkey, a, ok = c.Get("ch", ".", signatures[j])
			if ok || pkey.CompareTo(rainslib.PublicKey{}) != 0 || a != nil {
				t.Errorf("%d:Get should not return public key actual=(%v,%v)", i, pkey, ok)
			}
		}
		//lru removal
		ok = c.Add(delegationsORG[1], delegationsORG[1].Content[0].Value.(rainslib.PublicKey), false)
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
		c.Add(delegationsCH[3], delegationsCH[3].Content[0].Value.(rainslib.PublicKey), false)
		if c.Len() != 4 {
			t.Errorf("%d:Was not able to add expired delegation. expected=%d actual=%d", i, 3, c.Len())
		}
		c.RemoveExpiredKeys()
		if c.Len() != 3 {
			t.Errorf("%d:Was not able to remove expired delegation. expected=%d actual=%d", i, 2, c.Len())
		}
		//Test selfsigned root delegation
		ok = c.Add(delegationsORG[4], delegationsORG[4].Content[0].Value.(rainslib.PublicKey), false)
		if c.Len() != 4 {
			t.Errorf("%d:Delegation was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}
		pkey, a, ok = c.Get(".", ".", signatures[0])
		if !ok || pkey.CompareTo(delegationsORG[4].Content[0].Value.(rainslib.PublicKey)) != 0 ||
			!reflect.DeepEqual(a, delegationsORG[4]) {
			t.Errorf("%d:Get returned unexpected value actual=(%v,%v)", i, pkey, ok)
		}
	}
}

//FIXME CFE we cannot test if the cache logs correctly when the maximum number of delegations per
//zone is reached. Should we return a value if so in which form (object, error)?
func TestPendingKeyCache(t *testing.T) {
	a0 := &rainslib.AssertionSection{SubjectZone: "com", Context: "."}
	s1 := &rainslib.ShardSection{SubjectZone: "com", Context: "."}
	z2 := &rainslib.ZoneSection{SubjectZone: "ch", Context: "."}
	a3 := &rainslib.AssertionSection{SubjectZone: "ch", Context: "."}
	m := []msgSectionSender{
		msgSectionSender{Section: a0, Sender: rainslib.ConnInfo{}, Token: rainslib.GenerateToken()},
		msgSectionSender{Section: s1, Sender: rainslib.ConnInfo{}, Token: rainslib.GenerateToken()},
		msgSectionSender{Section: z2, Sender: rainslib.ConnInfo{}, Token: rainslib.GenerateToken()},
		msgSectionSender{Section: a3, Sender: rainslib.ConnInfo{}, Token: rainslib.GenerateToken()},
	}
	tokens := []rainslib.Token{rainslib.GenerateToken(), rainslib.GenerateToken()}
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
			sendQuery := c.Add(m[j], rainslib.Ed25519, 1)
			if c.Len() != j+1 {
				t.Errorf("%d.%d:section was not added to the cache. len=%d", i, j, c.Len())
			}
			if sendQuery != expectedValues[j] {
				t.Errorf("%d.%d:incorrect Add() return value. expected=%v actual=%v", i, j, expectedValues[j], sendQuery)
			}
		}
		//check that no matter what the new section is, it gets dropped in case the cache is full
		for j := 0; j < len(m); j++ {
			sendQuery := c.Add(m[j], rainslib.Ed25519, 1)
			if c.Len() != 3 {
				t.Errorf("%d.%d:section was added to the cache. len=%d", i, j, c.Len())
			}
			if sendQuery {
				t.Errorf("%d.%d:incorrect Add() return value. expected=false actual=%v", i, j, sendQuery)
			}
		}
		//Add token to cache entries
		ok := c.AddToken(rainslib.GenerateToken(), time.Now().Add(time.Second).Unix(), rainslib.ConnInfo{}, "de", ".")
		if ok {
			t.Errorf("%d:token added to non existing entry. len=%d", i, c.Len())
		}
		ok = c.AddToken(tokens[0], time.Now().Add(time.Second).Unix(), rainslib.ConnInfo{}, "com", ".")
		if !ok {
			t.Errorf("%d:wrong return value of addToken()", i)
		}
		ok = c.AddToken(tokens[1], time.Now().Add(time.Second).Unix(), rainslib.ConnInfo{}, "ch", ".")
		if !ok {
			t.Errorf("%d:wrong return value of addToken()", i)
		}
		//Check if token in cache
		newToken := rainslib.GenerateToken()
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
		v, ok := c.GetAndRemoveByToken(rainslib.GenerateToken())
		if ok || v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non matching token. len=%d", i, c.Len())
		}
		v, ok = c.GetAndRemoveByToken(tokens[0])
		if !ok || c.Len() != 1 || len(v) != 2 || (v[0] == m[0] && v[1] != m[1] || v[0] == m[1] && v[1] != m[0] || v[0] != m[0] && v[0] != m[1]) {
			t.Errorf(`%d:Token was not added to correct cacheValue by AddToken() or
			incorrect entries are removed from cache. len=%d returnValue=%v`, i, c.Len(), v)
		}
		//Check remaining Add() cases: same cacheValue and different algo type or phase;
		//same cacheValue, same algo, same hash
		sendQuery := c.Add(m[3], rainslib.Ed448, 1) //different algo type
		if c.Len() != 2 {
			t.Errorf("%d:section was not added to the cache. len=%d", i, c.Len())
		}
		if sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=false actual=%v", i, sendQuery)
		}
		sendQuery = c.Add(m[3], rainslib.Ed448, 1) //duplicate
		if c.Len() != 2 {
			t.Errorf("%d:same section was added again to the cache. len=%d", i, c.Len())
		}
		if sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=false actual=%v", i, sendQuery)
		}
		sendQuery = c.Add(m[3], rainslib.Ed25519, 0) //different phase
		if c.Len() != 3 {
			t.Errorf("%d:section was not added to the cache. len=%d", i, c.Len())
		}
		if sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=false actual=%v", i, sendQuery)
		}
		//Check GetAndRemove()
		//non existing elements
		v, ok = c.GetAndRemove("none contained zone", ".", rainslib.Ed25519, 0)
		if ok || v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		v, ok = c.GetAndRemove("ch", "non contained context", rainslib.Ed448, 0)
		if ok || v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		v, ok = c.GetAndRemove("ch", ".", rainslib.Ed448, 0)
		if ok || v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		v, ok = c.GetAndRemove("ch", ".", rainslib.Ed25519, 2)
		if ok || v != nil || c.Len() != 3 {
			t.Errorf("%d:Entry removed from cache with non argument. len=%d", i, c.Len())
		}
		//actual remove
		v, ok = c.GetAndRemove("ch", ".", rainslib.Ed448, 1)
		if !ok || c.Len() != 2 || len(v) != 1 || v[0] != m[3] {
			t.Errorf("%d:GetAndRemove() wrong return values. len=%d expectedValue= %v returnValue=%v", i, c.Len(), m[3], v[0])
		}
		v, ok = c.GetAndRemove("ch", ".", rainslib.Ed25519, 0)
		if !ok || c.Len() != 1 || len(v) != 1 || v[0] != m[3] {
			t.Errorf("%d:GetAndRemove() wrong return values. len=%d expectedValue= %v returnValue=%v", i, c.Len(), m[3], v[0])
		}
		v, ok = c.GetAndRemove("ch", ".", rainslib.Ed25519, 1)
		if !ok || c.Len() != 0 || len(v) != 1 || v[0] != m[2] {
			t.Errorf("%d:GetAndRemove() wrong return values. len=%d expectedValue= %v returnValue=%v", i, c.Len(), m[2], v[0])
		}
		//correct cleanup of hash map keys
		sendQuery = c.Add(m[0], rainslib.Ed25519, 0)
		if c.Len() != 1 {
			t.Errorf("%d:section was not added to the cache. len=%d", i, c.Len())
		}
		if !sendQuery {
			t.Errorf("%d:incorrect Add() return value. expected=true actual=%v", i, sendQuery)
		}
		ok = c.AddToken(tokens[0], time.Now().Unix(), rainslib.ConnInfo{}, "com", ".")
		if !ok {
			t.Errorf("%d:wrong return value of addToken().", i)
		}
		time.Sleep(2 * time.Second)
		//resend after expiration
		sendQuery = c.Add(m[0], rainslib.Ed25519, 0)
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

func TestAssertionCache(t *testing.T) {
	consistCache = &consistencyCacheImpl{
		ctxZoneMap: make(map[string]*consistencyCacheValue),
	}
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
		sections := consistCache.Get(aORG[0].SubjectZone, aORG[0].Context, aORG[0])
		if len(sections) != 1 || sections[0] != aORG[0] {
			t.Errorf("%d:Assertion was not added to consistency cache. expected=%v actual=%v", i, aORG[0], sections)
		}
		if ok := c.Add(assertions[0], assertions[0].ValidUntil(), false); !ok || c.Len() != 2 {
			t.Errorf("%d:Assertion was not added to cache. expected=%d actual=%d", i, 2, c.Len())
		}
		sections = consistCache.Get(assertions[0].SubjectZone, assertions[0].Context, assertions[0])
		if len(sections) != 1 || sections[0] != assertions[0] {
			t.Errorf("%d:Assertion was not added to consistency cache. expected=%v actual=%v", i, aORG[0], sections)
		}
		if ok := c.Add(assertions[1], assertions[1].ValidUntil(), false); !ok || c.Len() != 3 {
			t.Errorf("%d:Assertion was not added to cache. expected=%d actual=%d", i, 3, c.Len())
		}
		sections = consistCache.Get(assertions[0].SubjectZone, assertions[0].Context, assertions[0])
		if len(sections) != 2 {
			t.Errorf("%d:Assertion was not added to consistency cache. actual=%v", i, sections)
		}
		if ok := c.Add(assertions[2], assertions[2].ValidUntil(), false); ok || c.Len() != 1 {
			//All external assertions are removed because they have the same name, zone, ctx and type
			t.Errorf("%d:Assertion was not added to cache. expected=%d actual=%d", i, 1, c.Len())
		}
		c.Add(assertions[0], assertions[0].ValidUntil(), false)
		//Test Get
		//external element
		a, ok := c.Get(assertions[0].SubjectName, assertions[0].SubjectZone, assertions[0].Context,
			assertions[0].Content[0].Type)
		if !ok || len(a) != 1 || assertions[0] != a[0] {
			t.Errorf("%d:Was not able to get correct assertion from cache expected=%s actual=%s", i, assertions[0], a[0])
		}
		//internal element
		a, ok = c.Get(aORG[0].SubjectName, aORG[0].SubjectZone, aORG[0].Context, aORG[0].Content[0].Type)
		if !ok || len(a) != 1 || aORG[0] != a[0] {
			t.Errorf("%d:Was not able to get correct assertion from cache expected=%s actual=%s", i, aORG[0], a[0])
		}
		//more than one answer
		c.Add(assertions[1], assertions[1].ValidUntil(), false)
		a, ok = c.Get(assertions[0].SubjectName, assertions[0].SubjectZone, assertions[0].Context,
			assertions[0].Content[0].Type)
		if !ok || len(a) != 2 || (a[0] == assertions[0] && a[1] != assertions[1]) ||
			(a[0] == assertions[1] && a[1] != assertions[0]) || (a[0] == assertions[0] && a[0] == assertions[1]) {
			t.Errorf("%d:Was not able to get correct assertion from cache expected=%s actual=%s", i, assertions, a)
		}
		//Test Add with multiple objects
		aORG[1].Content = append(aORG[1].Content, rainslib.Object{Type: rainslib.OTIP4Addr, Value: "192.0.2.0"})
		if ok := c.Add(aORG[1], aORG[1].ValidUntil(), true); ok || c.Len() != 3 {
			//All external assertions are removed because they have the same name, zone, ctx and type
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}
		//Test RemoveZone
		c.RemoveZone(".")
		if c.Len() != 0 {
			t.Errorf("%d:Was not able to remove elements of zone '.' from cache.", i)
		}
		sections = consistCache.Get(".", ".", rainslib.TotalInterval{})
		if len(sections) != 0 {
			t.Errorf("%d:Assertions were not removed from consistency cache. actual=%v", i, sections)
		}
		//remove from internal and external
		c.Add(aORG[0], aORG[0].ValidUntil(), true)
		c.Add(assertions[1], assertions[1].ValidUntil(), false)
		c.RemoveZone(".")
		if c.Len() != 0 {
			t.Errorf("%d:Was not able to remove elements of zone '.' from cache.", i)
		}
		sections = consistCache.Get(".", ".", rainslib.TotalInterval{})
		if len(sections) != 0 {
			t.Errorf("%d:Assertions were not removed from consistency cache. actual=%v", i, sections)
		}
		//other zones are not affected
		assertions[2].SubjectZone = "com"
		c.Add(aORG[0], aORG[0].ValidUntil(), true)
		c.Add(assertions[2], assertions[2].ValidUntil(), false)
		c.RemoveZone("com")
		a, ok = c.Get(aORG[0].SubjectName, aORG[0].SubjectZone, aORG[0].Context, aORG[0].Content[0].Type)
		if c.Len() != 1 || a[0] != aORG[0] {
			t.Errorf("%d:Was not able to remove correct elements of zone '.' from cache.", i)
		}
		sections = consistCache.Get("com", ".", rainslib.TotalInterval{})
		if len(sections) != 0 {
			t.Errorf("%d:Assertions were not removed from consistency cache. actual=%v", i, sections)
		}
		sections = consistCache.Get(".", ".", rainslib.TotalInterval{})
		if len(sections) != 1 || sections[0] != aORG[0] {
			t.Errorf("%d:Assertions were not removed from consistency cache. actual=%v", i, sections)
		}
		//Test RemoveExpired for internal and external elements
		c.Add(aORG[3], aORG[3].ValidUntil(), true)
		c.Add(assertions[3], assertions[3].ValidUntil(), false)
		sections = consistCache.Get(".", ".", rainslib.TotalInterval{})
		if len(sections) != 3 {
			t.Errorf("%d:Assertions were not removed from consistency cache. actual=%v", i, sections)
		}
		c.RemoveExpiredValues()
		a, ok = c.Get(aORG[0].SubjectName, aORG[0].SubjectZone, aORG[0].Context, aORG[0].Content[0].Type)
		if c.Len() != 1 || a[0] != aORG[0] {
			t.Errorf("%d:Was not able to remove correct expired elements from cache.", i)
		}
		sections = consistCache.Get(".", ".", rainslib.TotalInterval{})
		if len(sections) != 1 || sections[0] != aORG[0] {
			t.Errorf("%d:Assertions were not removed from consistency cache. actual=%v", i, sections)
		}
	}
}

func TestNegAssertionCache(t *testing.T) {
	consistCache = &consistencyCacheImpl{
		ctxZoneMap: make(map[string]*consistencyCacheValue),
	}
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
		sections := consistCache.Get(zones[2].SubjectZone, zones[2].Context, zones[2])
		if len(sections) != 1 || sections[0] != zones[2] {
			t.Errorf("%d:Zone was not added to consistency cache. expected=%v actual=%v", i, zones[2], sections)
		}
		if ok := c.AddShard(shards[3], shards[3].ValidUntil(), false); !ok || c.Len() != 2 {
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 2, c.Len())
		}
		sections = consistCache.Get(shards[3].SubjectZone, shards[3].Context, shards[3])
		if len(sections) != 1 || sections[0] != shards[3] {
			t.Errorf("%d:Zone was not added to consistency cache. expected=%v actual=%v", i, zones[2], sections)
		}
		if ok := c.AddZone(zones[0], zones[0].ValidUntil(), false); !ok || c.Len() != 3 {
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}
		sections = consistCache.Get(zones[0].SubjectZone, zones[0].Context, zones[0])
		if len(sections) != 1 || sections[0] != zones[0] {
			t.Errorf("%d:Zone was not added to consistency cache. expected=%v actual=%v", i, zones[0], sections)
		}
		if ok := c.AddShard(shards[1], shards[1].ValidUntil(), false); ok || c.Len() != 3 {
			t.Errorf("%d:Assertion was not added to cache expected=%d actual=%d", i, 3, c.Len())
		}
		sections = consistCache.Get(shards[1].SubjectZone, shards[1].Context, shards[1])
		if len(sections) != 2 || (sections[0] == shards[1] && sections[1] != zones[0]) ||
			(sections[0] == zones[0] && sections[1] != shards[1]) ||
			(sections[0] != zones[0] && sections[0] != shards[1]) {
			t.Errorf("%d:Not the correct sections have been returned or added. actual=%v", i, sections)
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
		sections = consistCache.Get("org", zones[2].Context, zones[2])
		if len(sections) != 0 {
			t.Errorf("%d:Was not able to remove zone from consistency cache. actual=%v", i, sections)
		}
		sections = consistCache.Get("org", shards[3].Context, zones[2])
		if len(sections) != 0 {
			t.Errorf("%d:Was not able to remove shard from consistency cache. actual=%v", i, sections)
		}
		//Test RemoveZone external
		c.RemoveZone("ch")
		if c.Len() != 0 {
			t.Errorf("%d:Was not able to remove elements of zone '.' from cache.", i)
		}
		sections = consistCache.Get("ch", zones[0].Context, zones[0])
		if len(sections) != 0 {
			t.Errorf("%d:Was not able to remove shard from consistency cache. actual=%v", i, sections)
		}
		//Test RemoveExpired from internal and external elements
		c.AddZone(zones[2], zones[2].ValidUntil(), true)
		c.AddShard(shards[4], shards[4].ValidUntil(), false)
		c.AddShard(shards[0], shards[0].ValidUntil(), false)
		c.RemoveExpiredValues()
		s, ok = c.Get(shards[0].SubjectZone, shards[0].Context, rainslib.TotalInterval{})
		if c.Len() != 1 || s[0] != shards[0] {
			t.Errorf("%d:Was not able to remove correct expired elements from cache.", i)
		}
		sections = consistCache.Get("ch", shards[0].Context, zones[0])
		if len(sections) != 1 || sections[0] != shards[0] {
			t.Errorf("%d:Removed wrong shard from consistency cache. actual=%v", i, sections)
		}
		sections = consistCache.Get(shards[4].SubjectZone, shards[4].Context, shards[4])
		if len(sections) != 0 {
			t.Errorf("%d:Was not able to remove shard from consistency cache. actual=%v", i, sections)
		}
		sections = consistCache.Get(zones[2].SubjectZone, zones[2].Context, zones[2])
		if len(sections) != 0 {
			t.Errorf("%d:Was not able to remove zone from consistency cache. actual=%v", i, sections)
		}
	}
}

func TestConsistencyCache(t *testing.T) {
	var tests = []struct {
		input consistencyCache
	}{
		{
			&consistencyCacheImpl{
				ctxZoneMap: make(map[string]*consistencyCacheValue),
			},
		},
	}
	for i, test := range tests {
		c := test.input
		assertions := getAssertions()
		shards := getShards()
		zones := getZones()
		//Test Add
		c.Add(assertions[0])
		c.Add(shards[0])
		c.Add(zones[2])
		//Test Get
		sections := c.Get(shards[0].SubjectZone, shards[0].Context, assertions[0])
		if len(sections) != 2 || (sections[0] == shards[0] && sections[1] != assertions[0]) ||
			(sections[0] == assertions[0] && sections[1] != shards[0]) ||
			(sections[0] != assertions[0] && sections[0] != shards[0]) {
			t.Errorf("%d:Not the correct sections have been returned or added. actual=%v", i, sections)
		}
		//Get border case: point is on the interval border (interval borders are exclusive)
		sections = c.Get(shards[0].SubjectZone, shards[0].Context,
			rainslib.StringInterval{Name: shards[0].End()})
		if len(sections) != 0 {
			t.Errorf("%d:Border should be excluding. actual=%v", i, sections)
		}
		sections = c.Get(zones[2].SubjectZone, zones[2].Context, rainslib.StringInterval{Name: "m"})
		if len(sections) != 1 || sections[0] != zones[2] {
			t.Errorf("%d:Not the correct sections have been returned or added. actual=%v", i, sections)
		}
		//Test Remove
		c.Remove(zones[2])
		sections = c.Get(zones[2].SubjectZone, zones[2].Context, rainslib.StringInterval{Name: "m"})
		if len(sections) != 0 {
			t.Errorf("%d:Not the correct element was removed. actual=%v", i, sections)
		}
		c.Remove(assertions[0])
		sections = c.Get(shards[0].SubjectZone, shards[0].Context, assertions[0])
		if len(sections) != 1 || sections[0] != shards[0] {
			t.Errorf("%d:Not the correct element was removed. actual=%v", i, sections)
		}
		c.Remove(shards[0])
		sections = c.Get(shards[0].SubjectZone, shards[0].Context, assertions[0])
		if len(sections) != 0 {
			t.Errorf("%d:Not the correct element was removed. actual=%v", i, sections)
		}
	}
}

func getExampleDelgations(tld string) []*rainslib.AssertionSection {
	a1 := &rainslib.AssertionSection{
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a2 := &rainslib.AssertionSection{ //same key phase as a1 but different key and validity period
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
					ValidSince:  time.Now().Add(25 * time.Hour).Unix(),
					ValidUntil:  time.Now().Add(48 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey2")),
				},
			},
		},
	}
	a3 := &rainslib.AssertionSection{ //different keyphase, everything else the same as a1
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 1},
					ValidSince:  time.Now().Unix(),
					ValidUntil:  time.Now().Add(24 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	//expired delegation assertion
	a4 := &rainslib.AssertionSection{ //different keyphase, everything else the same as a1
		SubjectName: tld,
		SubjectZone: ".",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 1},
					ValidSince:  time.Now().Add(-2 * time.Hour).Unix(),
					ValidUntil:  time.Now().Add(-1 * time.Hour).Unix(),
					Key:         ed25519.PublicKey([]byte("TestKey")),
				},
			},
		},
	}
	a5 := &rainslib.AssertionSection{ //different keyphase, everything else the same as a1
		SubjectName: "@",
		SubjectZone: ".",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
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
	return []*rainslib.AssertionSection{a1, a2, a3, a4, a5}
}

func getSignatureMetaData() []rainslib.SignatureMetaData {
	//signature in the interval of the above public keys
	s1 := rainslib.SignatureMetaData{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(23 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
	}
	s2 := rainslib.SignatureMetaData{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
		ValidUntil:  time.Now().Add(30 * time.Hour).Unix(),
	}
	s3 := rainslib.SignatureMetaData{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 1},
		ValidSince:  time.Now().Add(23 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(24*time.Hour + 30*time.Minute).Unix(),
	}
	//signature not in the interval of the above public keys
	s4 := rainslib.SignatureMetaData{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(-2 * time.Hour).Unix(),
		ValidUntil:  time.Now().Add(-1 * time.Hour).Unix(),
	}
	s5 := rainslib.SignatureMetaData{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(48*time.Hour + 1).Unix(),
		ValidUntil:  time.Now().Add(50 * time.Hour).Unix(),
	}
	s6 := rainslib.SignatureMetaData{
		PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 0},
		ValidSince:  time.Now().Add(24*time.Hour + 1).Unix(),
		ValidUntil:  time.Now().Add(25*time.Hour - 1).Unix(),
	}

	return []rainslib.SignatureMetaData{s1, s2, s3, s4, s5, s6}
}

func getAssertions() []*rainslib.AssertionSection {
	s0 := &rainslib.AssertionSection{
		SubjectName: "b",
		SubjectZone: "ch",
		Context:     ".",
	}
	s1 := &rainslib.AssertionSection{
		SubjectName: "e",
		SubjectZone: "ch",
		Context:     ".",
	}
	s2 := &rainslib.AssertionSection{
		SubjectName: "a",
		SubjectZone: "org",
		Context:     ".",
	}
	s3 := &rainslib.AssertionSection{
		SubjectName: "b",
		SubjectZone: "org",
		Context:     "test-cch",
	}
	return []*rainslib.AssertionSection{s0, s1, s2, s3}
}

func getShards() []*rainslib.ShardSection {
	s0 := &rainslib.ShardSection{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "a",
		RangeTo:     "c",
	}
	s1 := &rainslib.ShardSection{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "a",
		RangeTo:     "b",
	}
	s2 := &rainslib.ShardSection{
		SubjectZone: "ch",
		Context:     ".",
		RangeFrom:   "c",
		RangeTo:     "f",
	}
	s3 := &rainslib.ShardSection{
		SubjectZone: "org",
		Context:     ".",
		RangeFrom:   "c",
		RangeTo:     "z",
	}
	s4 := &rainslib.ShardSection{
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
	return []*rainslib.ShardSection{s0, s1, s2, s3, s4}
}

func getZones() []*rainslib.ZoneSection {
	s0 := &rainslib.ZoneSection{
		SubjectZone: "ch",
		Context:     ".",
	}
	s1 := &rainslib.ZoneSection{
		SubjectZone: "org",
		Context:     ".",
	}
	s2 := &rainslib.ZoneSection{
		SubjectZone: "org",
		Context:     "test-cch",
	}
	s0.UpdateValidity(time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), 24*time.Hour)
	s1.UpdateValidity(time.Now().Unix(), time.Now().Add(48*time.Hour).Unix(), 48*time.Hour)
	s2.UpdateValidity(time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), time.Hour)
	return []*rainslib.ZoneSection{s0, s1, s2}
}
