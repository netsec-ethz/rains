package cache

import (
	"crypto/sha256"
	"fmt"
	"sort"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/lruCache"
	"github.com/netsec-ethz/rains/internal/pkg/message"
)

/*
 *	Capability cache implementation
 */
type CapabilityImpl struct {
	capabilityMap *lruCache.Cache
	counter       *safeCounter.Counter
}

func NewCapability(maxSize int) *CapabilityImpl {
	cache := &CapabilityImpl{
		capabilityMap: lruCache.New(),
		counter:       safeCounter.New(maxSize),
	}
	cache.capabilityMap.GetOrAdd("e5365a09be554ae55b855f15264dbc837b04f5831daeb321359e18cdabab5745",
		[]message.Capability{message.TLSOverTCP}, true)
	cache.capabilityMap.GetOrAdd("76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71",
		[]message.Capability{message.NoCapability}, false)
	cache.counter.Add(2)
	return cache
}

func (c *CapabilityImpl) Add(capabilities []message.Capability) {
	//FIXME CFE take a SHA-256 hash of the CBOR byte stream derived from normalizing such an array by sorting it in lexicographically increasing order,
	//then serializing it and add it to the cache
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i] < capabilities[j] })
	cs := []byte{}
	for _, c := range capabilities {
		cs = append(cs, []byte(c)...)
	}
	hash := sha256.Sum256(cs)
	_, ok := c.capabilityMap.GetOrAdd(string(hash[:]), capabilities, false)
	//handle full cache
	if ok && c.counter.Inc() {
		for {
			k, _ := c.capabilityMap.GetLeastRecentlyUsed()
			if _, ok := c.capabilityMap.Remove(k); ok {
				c.counter.Dec()
				break
			}
		}
	}
}

func (c *CapabilityImpl) Get(hash []byte) ([]message.Capability, bool) {
	if v, ok := c.capabilityMap.Get(string(hash)); ok {
		if val, ok := v.([]message.Capability); ok {
			return val, true
		}
		log.Warn("Cache entry is not of type []message.Capability",
			"actualType", fmt.Sprintf("%T", v))
	}
	return nil, false
}

func (c *CapabilityImpl) Len() int {
	return c.counter.Value()
}
