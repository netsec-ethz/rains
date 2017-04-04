package assertionCache

import (
	basicCache "rains/utils/cache"
	"rains/utils/set"
	"sort"
	"sync"
)

type elem struct {
	name string
	set  *set.Set
}

//Cache is a LRU cache where some elements are not subject to the LRU removal strategy. This cache is safe for concurrent use.
type Cache struct {
	//TODO CFE maybe remove locks from cache so we do not have to lock it twice here and have a separate thread safe cache for operation solely on cache.
	mux sync.RWMutex

	//cache for fast access to set of assertions
	cache *basicCache.Cache
	//sortedAssertions has key <context:zone>. It is used to find all assertions in a given range for a context and zone
	sortedAssertions map[string][]elem
}

//New creates a cache where the first parameter entry must contain the maximum size of the cache (>0).
//The second Parameter specifies if cacheAnyContext is used. on input 'anyContext' is it used and on 'noAnyContext' not.
func New(params ...interface{}) (*Cache, error) {
	cache := Cache{
		sortedAssertions: make(map[string][]elem),
	}
	//deletes element from
	onEvicted := func(value interface{}, key ...string) {
		elements, ok := cache.sortedAssertions[key[0]+":"+key[1]]
		if ok {
			index := sort.Search(len(elements), func(i int) bool {
				return elements[i].name >= key[2]
			})
			if index != len(elements) {
				cache.sortedAssertions[key[0]+":"+key[1]] = append(elements[:index], elements[index+1:]...)
			}
		}
	}
	bCache, err := basicCache.NewWithEvict(onEvicted, params)
	if err != nil {
		return nil, err
	}
	cache.cache = bCache
	return &cache, nil
}

//Add adds a value to the cache and sortedAssertion data structure.
//If the cache is full the least recently used non internal element will be replaced. Returns true if it added an element.
func (c *Cache) Add(value interface{}, internal bool, context string, keys ...string) bool {
	c.mux.Lock()
	defer c.mux.Unlock()
	ok := c.cache.Add(value, internal, context, keys...)
	if ok {
		if elements, ok := c.sortedAssertions[context+":"+keys[0]]; ok {
			i := getIndex(elements, keys[1])
			//TODO CFE does this work also when there is just one element in the slice
			c.sortedAssertions[context+":"+keys[0]] = append(elements[:i], append([]elem{elem{name: keys[1], set: value.(*set.Set)}}, elements[i:]...)...)
		} else {
			c.sortedAssertions[context+":"+keys[0]] = []elem{elem{name: keys[1], set: value.(*set.Set)}}
		}

	}
	return ok
}

func getIndex(elements []elem, key string) int {
	return sort.Search(len(elements), func(i int) bool { return elements[i].name >= key })
}

//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
func (c *Cache) Contains(context string, keys ...string) bool {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.cache.Contains(context, keys...)
}

//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
func (c *Cache) Get(context string, keys ...string) (interface{}, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.cache.Get(context, keys...)
}

//Keys returns a slice of the keys in the cache
func (c *Cache) Keys() []interface{} {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.cache.Keys()
}

//Len returns the number of elements in the cache.
func (c *Cache) Len() int {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.cache.Len()
}

//Remove deletes the key value pair from the cache and sortedAssertion data structure based on the given key
func (c *Cache) Remove(context string, keys ...string) bool {
	c.mux.Lock()
	defer c.mux.Unlock()
	//sorted slice will be updated by onEvict function of cache.
	return c.cache.Remove(context, keys...)
}

//RemoveWithStrategy deletes the least recently used key value pair from the cache and sortedAssertion data structure
func (c *Cache) RemoveWithStrategy() bool {
	c.mux.Lock()
	defer c.mux.Unlock()
	//sorted slice will be updated by onEvict function of cache.
	return c.cache.RemoveWithStrategy()
}

//GetInRange returns sets of assertions grouped by context and zone which are in the given range.
func (c *Cache) GetInRange(context, zone, begin, end string) []*set.Set {
	elements := c.sortedAssertions[context+":"+zone]
	sets := []*set.Set{}
	for i := getIndex(elements, begin); elements[i].name < end; i++ {
		sets = append(sets, elements[i].set)
	}
	return sets
}
