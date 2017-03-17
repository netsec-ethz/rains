package rainsd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"rains/rainslib"
	"strconv"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

const (
	configPath = "config/server.conf"
)

//rainsdConfig lists possible configurations of a rains server
type rainsdConfig struct {
	//switchboard
	ServerIPAddr    string
	ServerPort      uint16
	MaxConnections  uint
	KeepAlivePeriod time.Duration
	TCPTimeout      time.Duration
	CertificateFile string
	PrivateKeyFile  string

	//inbox
	PrioBufferSize   uint
	NormalBufferSize uint
	PrioWorkerSize   uint
	NormalWorkerSize uint

	//verify
	ZoneKeyCacheSize          uint
	PendingSignatureCacheSize uint

	//engine
	AssertionCacheSize    uint
	PendingQueryCacheSize uint

	//notification
	CapabilitiesCacheSize uint
}

//DefaultConfig is a rainsdConfig object containing default values
var defaultConfig = rainsdConfig{ServerIPAddr: "127.0.0.1", ServerPort: 5022, MaxConnections: 1000, KeepAlivePeriod: time.Minute, TCPTimeout: 5 * time.Minute,
	CertificateFile: "config/server.crt", PrivateKeyFile: "config/server.key", PrioBufferSize: 1000, NormalBufferSize: 100000, PrioWorkerSize: 2, NormalWorkerSize: 10,
	ZoneKeyCacheSize: 1000, PendingSignatureCacheSize: 1000, AssertionCacheSize: 10000, PendingQueryCacheSize: 100, CapabilitiesCacheSize: 100}

//ProtocolType enumerates protocol types
type ProtocolType int

const (
	TCP ProtocolType = iota
)

//ConnInfo contains address information about one actor of a connection of the declared type
//type 1 contains IPAddr and Port information
type ConnInfo struct {
	Type   ProtocolType
	IPAddr string
	Port   uint16
}

//MsgSender contains the message and connection infos about the sender
type MsgSender struct {
	Sender ConnInfo
	Msg    rainslib.MessageBody
}

//IPAddrAndPort returns IP address and port in the format IPAddr:Port
func (c ConnInfo) IPAddrAndPort() string {
	return c.IPAddr + ":" + c.PortToString()
}

//PortToString return the port number as a string
func (c ConnInfo) PortToString() string {
	return strconv.Itoa(int(c.Port))
}

//Config contains configurations for this server
var Config rainsdConfig

//load config and stores it into global variable config
func loadConfig() {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal("Could not open config file...", "path", configPath, "error", err)
	}
	json.Unmarshal(file, &Config)
}

//Cache implementations can have different replacement strategies
type Cache interface {
	//New creates a cache with the given parameters
	New(params ...interface{}) error
	//NewWithEvict creates a cache with the given parameters and a callback function when an element gets evicted
	NewWithEvict(onEvicted func(key interface{}, value interface{}), params ...interface{}) error
	//Add adds a value to the cache. If the cache is full the oldest element according to some metric will be replaced. Returns true if an eviction occurred.
	Add(key, value interface{}) bool
	//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
	Contains(key interface{}) bool
	//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
	Get(key interface{}) (interface{}, bool)
	//Len returns the number of elements in the cache.
	Len() int
	//Remove deletes the given key value pair from the cache
	Remove(key interface{})
	//RemoveOldest deletes the given key value pair from the cache according to some metric
	RemoveOldest()
}

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

//Len returns the number of elements in the cache.
func (c *LRUCache) Len() int {
	return c.Cache.Len()
}

//Remove deletes the given key value pair from the cache
func (c *LRUCache) Remove(key interface{}) {
	c.Cache.Remove(key)
}

//RemoveOldest deletes the least recently used key value pair from the cache
func (c *LRUCache) RemoveOldest() {
	c.Cache.RemoveOldest()
}
