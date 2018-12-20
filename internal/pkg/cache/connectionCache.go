package cache

import (
	"fmt"
	"net"
	"sync"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/message"
)

//connCacheValue is the value pointed to by the hash map in the ConnectionImpl
type connCacheValue struct {
	connections  []net.Conn
	capabilities []message.Capability

	mux sync.RWMutex
	//set to true if the pointer to this element is removed from the hash map
	deleted bool
}

/*
 *	Connection cache implementation
 */
type ConnectionImpl struct {
	cache   *lruCache.Cache
	counter *safeCounter.Counter
}

func NewConnection(maxSize int) *ConnectionImpl {
	return &ConnectionImpl{
		cache:   lruCache.New(),
		counter: safeCounter.New(maxSize),
	}
}

func getNetworkAndAddr(conn net.Conn) string {
	return fmt.Sprintf("%s %s", conn.RemoteAddr().Network(), conn.RemoteAddr())
}

//AddConnection adds conn to the cache. If the cache is full the least recently used connection is removed.
func (c *ConnectionImpl) AddConnection(conn net.Conn) {
	v := &connCacheValue{connections: []net.Conn{}}
	e, _ := c.cache.GetOrAdd(getNetworkAndAddr(conn), v, false)
	value := e.(*connCacheValue)
	value.mux.Lock()
	value.connections = append(value.connections, conn)
	value.mux.Unlock()
	if c.counter.Inc() {
		//cache is full, remove all connections from the least recently used destination
		for {
			if !c.counter.IsFull() {
				break
			}
			key, e := c.cache.GetLeastRecentlyUsed()
			value := e.(*connCacheValue)
			value.mux.Lock()
			if value.deleted {
				value.mux.Unlock()
				continue
			}
			value.deleted = true
			for _, conn := range value.connections {
				conn.Close()
				c.counter.Dec()
			}
			c.cache.Remove(key)
			value.mux.Unlock()
			break
		}
	}
}

//AddCapability adds capabilities to the destAddr entry. It returns false if there is no entry in
//the cache for dstAddr. If there is already a capability list associated with destAddr, it will be
//overwritten.
func (c *ConnectionImpl) AddCapabilityList(dstAddr connection.Info, capabilities []message.Capability) bool {
	if e, ok := c.cache.Get(dstAddr.NetworkAndAddr()); ok {
		v := e.(*connCacheValue)
		v.mux.Lock()
		defer v.mux.Unlock()
		if v.deleted {
			return false
		}
		v.capabilities = capabilities
		return true
	}
	return false
}

//GetConnection returns true and all cached connection objects to dstAddr.
//GetConnection returns false if there is no cached connection to dstAddr.
func (c *ConnectionImpl) GetConnection(dstAddr connection.Info) ([]net.Conn, bool) {
	if e, ok := c.cache.Get(dstAddr.NetworkAndAddr()); ok {
		v := e.(*connCacheValue)
		v.mux.RLock()
		defer v.mux.RUnlock()
		if v.deleted {
			return nil, false
		}
		return v.connections, true
	}
	return nil, false
}

//Get returns true and the capability list of dstAddr.
//Get returns false if there is no capability list of dstAddr.
func (c *ConnectionImpl) GetCapabilityList(dstAddr connection.Info) ([]message.Capability, bool) {
	if e, ok := c.cache.Get(dstAddr.NetworkAndAddr()); ok {
		v := e.(*connCacheValue)
		v.mux.RLock()
		defer v.mux.RUnlock()
		if v.deleted {
			return nil, false
		}
		return v.capabilities, true
	}
	return nil, false
}

//Delete closes conn and removes it from the cache
func (c *ConnectionImpl) CloseAndRemoveConnection(conn net.Conn) {
	conn.Close()
	if e, ok := c.cache.Get(getNetworkAndAddr(conn)); ok {
		v := e.(*connCacheValue)
		v.mux.Lock()
		defer v.mux.Unlock()
		if !v.deleted {
			if len(v.connections) > 1 {
				for i, connection := range v.connections {
					if connection == conn {
						v.connections = append((v.connections)[:i], (v.connections)[i+1:]...)
						c.counter.Dec()
					}
				}
			} else {
				v.deleted = true
				c.cache.Remove(getNetworkAndAddr(conn))
				c.counter.Dec()
			}
		}
	}
}

func (c *ConnectionImpl) Len() int {
	return c.counter.Value()
}
