package rainsd

import (
	"bufio"
	"crypto/rand"
	"net"
	"rains/utils/cache"

	"fmt"

	lru "github.com/hashicorp/golang-lru"
	log "github.com/inconshreveable/log15"
)

type newLineFramer struct {
	Scanner   *bufio.Scanner
	firstCall bool
}

func (f newLineFramer) Frame(msg []byte) ([]byte, error) {
	return append(msg, "\n"...), nil
}

func (f *newLineFramer) Deframe() bool {
	if f.firstCall {
		f.Scanner.Split(bufio.ScanLines)
		f.firstCall = false
	}
	return f.Scanner.Scan()
}

func (f newLineFramer) Data() []byte {
	return f.Scanner.Bytes()
}

//PRG pseudo random generator
type PRG struct{}

func (prg PRG) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

//TODO CFE replace this with an own implementation
//LRUCache is a concurrency safe cache with a least recently used eviction strategy
type LRUCache struct {
	Cache *lru.Cache
}

//New creates a lru cache with the given parameters
func (c *LRUCache) New(params ...interface{}) error {
	var err error
	c.Cache, err = lru.New(params[0].(int))
	return err
}

//NewWithEvict creates a lru cache with the given parameters and an eviction callback function
func (c *LRUCache) NewWithEvict(onEvicted func(key interface{}, value interface{}), params ...interface{}) error {
	var err error
	c.Cache, err = lru.NewWithEvict(params[0].(int), onEvicted)
	return err
}

//Add adds a value to the cache. If the cache is full the least recently used element will be replaced. Returns true if an eviction occurred.
func (c *LRUCache) Add(key, value interface{}) bool {
	return c.Cache.Add(key, value)
}

//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
func (c *LRUCache) Contains(key interface{}) bool {
	return c.Cache.Contains(key)
}

//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	return c.Cache.Get(key)
}

//Keys returns a slice of the keys in the cache sorted from oldest to newest
func (c *LRUCache) Keys() []interface{} {
	return c.Cache.Keys()
}

//Len returns the number of elements in the cache.
func (c *LRUCache) Len() int {
	return c.Cache.Len()
}

//Remove deletes the given key value pair from the cache
func (c *LRUCache) Remove(key interface{}) {
	c.Cache.Remove(key)
}

//RemoveWithStrategy deletes the least recently used key value pair from the cache
func (c *LRUCache) RemoveWithStrategy() {
	c.Cache.RemoveOldest()
}

type connectionCacheImpl struct {
	cache *cache.Cache
}

func (c connectionCacheImpl) Add(connInfo string, conn net.Conn) bool {
	return c.cache.Add(conn, false, "", connInfo)
}

func (c connectionCacheImpl) Get(connInfo string) (net.Conn, bool) {
	if v, ok := c.cache.Get("", connInfo); ok {
		if val, ok := v.(net.Conn); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type net.Conn", "type", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c connectionCacheImpl) Len() int {
	return c.cache.Len()
}
