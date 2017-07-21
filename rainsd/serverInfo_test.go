package rainsd

import (
	"bufio"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/lruCache"
	"github.com/netsec-ethz/rains/utils/safeCounter"
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
		{&connectionCacheImpl{cache: lruCache.New(), counter: safeCounter.New(2)}},
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

func TestZoneKeyCache(t *testing.T) {
	var tests = []struct {
		input zonePublicKeyCache
	}{
		{&zoneKeyCacheImpl{zoneHashMap: lruCache.New(), counter: safeCounter.New(4), warnSize: 3, maxPublicKeysPerZone: 2}},
	}
	for i, test := range tests {
		c := test.input
		if c.Len() != 0 {
			t.Errorf("%d:init size is incorrect actual=%d", i, c.Len())
		}
		//Add delegationAssertions
	}
}

func getExampleCOM() []*rainslib.AssertionSection {
	a1 := &rainslib.AssertionSection{
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
					ValidSince:  1000,
					ValidUntil:  2000,
					Key:         []byte("TestKey"),
				},
			},
		},
	}
	a2 := &rainslib.AssertionSection{ //different key, everything else the same as a1
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519},
					ValidSince:  1000,
					ValidUntil:  2000,
					Key:         []byte("TestKey2"),
				},
			},
		},
	}
	a3 := &rainslib.AssertionSection{ //different keyphase, everything else the same as a1
		SubjectName: "example",
		SubjectZone: "com",
		Context:     ".",
		Content: []rainslib.Object{
			rainslib.Object{
				Type: rainslib.OTDelegation,
				Value: rainslib.PublicKey{
					PublicKeyID: rainslib.PublicKeyID{Algorithm: rainslib.Ed25519, KeyPhase: 1},
					ValidSince:  1000,
					ValidUntil:  2000,
					Key:         []byte("TestKey"),
				},
			},
		},
	}
	return []*rainslib.AssertionSection{a1, a2, a3}
}
