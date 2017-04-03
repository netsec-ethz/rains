package cache

import (
	"container/list"
	"fmt"
	"sync"
)

//TODO CFE Performance optimization: do not lock whole cache when updating but only lock part of the list

//Cache is a LRU cache where some elements are not subject to the LRU removal strategy. This cache is safe for concurrent use.
type Cache struct {
	//maxEntries is the maximum number of cache entries before an item is evicted.
	maxEntries int

	//hasAnyContext is true if cache also supports any context
	hasAnyContext bool

	//onEvicted optionally specifies a callback function to be executed when an entry is removed from the cache.
	onEvicted func(value interface{}, key ...string)

	mux sync.RWMutex

	list            *list.List //contains elements that are not affected by LRU removal strategy
	lruList         *list.List
	cache           map[string]*list.Element
	cacheAnyContext map[string]*list.Element
}

type entry struct {
	internal bool
	context  string
	key      string
	value    interface{}
}

//New creates a cache where the first parameter entry must contain the maximum size of the cache (>0).
//The second Parameter specifies if cacheAnyContext is used. on input 'context' is it used and on 'noContext' not.
func New(params ...interface{}) (*Cache, error) {
	maxSize, anyContext, err := checkParams(params...)
	if err != nil {
		return nil, err
	}
	cache := Cache{
		maxEntries:    maxSize,
		hasAnyContext: anyContext,
		list:          list.New(),
		lruList:       list.New(),
		cache:         make(map[string]*list.Element),
	}
	if anyContext {
		cache.cacheAnyContext = make(map[string]*list.Element)
	}
	return &cache, nil
}

//NewWithEvict creates a cache with the given parameters and a callback function when an element gets evicted
func NewWithEvict(onEvicted func(value interface{}, key ...string), params ...interface{}) (*Cache, error) {
	maxSize, anyContext, err := checkParams(params...)
	if err != nil {
		return nil, err
	}
	cache := Cache{
		maxEntries:    maxSize,
		hasAnyContext: anyContext,
		onEvicted:     onEvicted,
		list:          list.New(),
		lruList:       list.New(),
		cache:         make(map[string]*list.Element),
	}
	if anyContext {
		cache.cacheAnyContext = make(map[string]*list.Element)
	}
	return &cache, nil
}

func checkParams(params ...interface{}) (int, bool, error) {
	if len(params) < 2 {
		return 0, false, fmt.Errorf("Not enough parameters, got %d, with values: param1=%v", len(params), params)
	}
	maxSize, ok := params[0].(int)
	if !ok || maxSize < 1 {
		return 0, false, fmt.Errorf("Invalid maxEntries parameter:%v", params[0])
	}
	if params[1] == "anyContext" {
		return maxSize, true, nil
	}
	if params[1] == "noAnyContext" {
		return maxSize, false, nil
	}
	return 0, false, fmt.Errorf("Invalid value on second parameter (hasAnyContext): param2=%v", params[1])
}

//Add adds a value to the cache. If the cache is full the least recently used non internal element will be replaced. Returns true if it added an element.
func (c *Cache) Add(value interface{}, internal bool, context string, keys ...string) bool {
	if c.cache == nil {
		c.hasAnyContext = true
		c.list = list.New()
		c.lruList = list.New()
		c.cache = make(map[string]*list.Element)
		c.cacheAnyContext = make(map[string]*list.Element)
	}
	key := parseKeys(keys)
	c.mux.Lock()
	if v, ok := c.cache[context+":"+key]; ok {
		if internal {
			if !v.Value.(*entry).internal {
				//value exist in external list, move it to internal
				c.lruList.Remove(v)
				c.list.PushFront(v)
			} else {
				//value exist in correct list
				c.list.MoveToFront(v)
			}
		} else {
			if v.Value.(*entry).internal {
				//value exist in internal list, move it to external list.
				c.list.Remove(v)
				c.lruList.PushFront(v)
			} else {
				//value exist in correct list
				c.lruList.MoveToFront(v)
			}
		}
		return false
	}
	//key does not already exist in cache
	var element *list.Element
	if internal {
		element = c.list.PushFront(&entry{internal: true, context: context, key: key, value: value})
	} else {
		element = c.lruList.PushFront(&entry{internal: false, context: context, key: key, value: value})
	}
	c.cache[context+":"+key] = element
	if c.hasAnyContext {
		c.cacheAnyContext[key] = element
	}
	c.mux.Unlock()

	//check if cache size is reached
	if c.Len() > c.maxEntries {
		c.RemoveWithStrategy()
	}
	return true
}

func parseKeys(keys []string) string {
	key := keys[0]
	for _, k := range keys[1:] {
		key += ":" + k
	}
	return key
}

//Contains checks if a key is in the cache, without updating the recentness or deleting it for being stale.
func (c *Cache) Contains(context string, keys ...string) bool {
	key := parseKeys(keys)
	c.mux.RLock()
	defer c.mux.RUnlock()
	var contained bool
	if c.hasAnyContext && context == "" {
		_, contained = c.cacheAnyContext[key]
	} else {
		_, contained = c.cache[context+":"+key]
	}
	return contained
}

//Get returns the key's value from the cache. The boolean value is false if there exist no element with the given key in the cache
func (c *Cache) Get(context string, keys ...string) (interface{}, bool) {
	key := parseKeys(keys)
	c.mux.RLock()
	defer c.mux.RUnlock()
	var v *list.Element
	var ok bool
	if c.hasAnyContext && context == "" {
		v, ok = c.cacheAnyContext[key]
	} else {
		v, ok = c.cache[context+":"+key]
	}
	if !ok {
		return nil, false
	}
	return v.Value.(*entry).value, true
}

//Keys returns a slice of the keys in the cache
func (c *Cache) Keys() []interface{} {
	c.mux.RLock()
	defer c.mux.RUnlock()
	keys := []interface{}{}
	for key := range c.cache {
		keys = append(keys, key)
	}
	return keys
}

//Len returns the number of elements in the cache.
func (c *Cache) Len() int {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.list.Len() + c.lruList.Len()
}

//Remove deletes the key value pair from the cache based on the given key
func (c *Cache) Remove(context string, keys ...string) bool {
	key := parseKeys(keys)
	c.mux.Lock()
	defer c.mux.Unlock()
	if element, ok := c.cache[context+":"+key]; ok {
		if element.Value.(*entry).internal {
			c.list.Remove(element)
		} else {
			c.lruList.Remove(element)
		}
		delete(c.cache, context+":"+key)
		if c.hasAnyContext {
			delete(c.cacheAnyContext, key)
		}
		if c.onEvicted != nil {
			c.onEvicted(element.Value.(*entry).value, context+":"+key)
		}
		return true
	}
	return false
}

//RemoveWithStrategy deletes the least recently used key value pair from the cache
func (c *Cache) RemoveWithStrategy() bool {
	c.mux.Lock()
	defer c.mux.Unlock()
	element := c.lruList.Back()
	if element == nil {
		return false
	}
	c.lruList.Remove(element)
	value := element.Value.(*entry)
	delete(c.cache, value.context+":"+value.key)
	if c.hasAnyContext {
		delete(c.cacheAnyContext, value.key)
	}
	if c.onEvicted != nil {
		c.onEvicted(value.value, value.context+":"+value.key)
	}
	return true
}
