package lruCache

import (
	"container/list"
	"sync"

	log "github.com/inconshreveable/log15"
)

// Cache is a LRU cache where some elements are not subject to the LRU removal strategy. This cache is safe for concurrent use.
type Cache struct {
	mux sync.RWMutex

	internalList *list.List //values in the internalList are only explicitly removed
	lruList      *list.List
	hashMap      map[string]*list.Element
}

type entry struct {
	internal bool
	key      string
	value    interface{}
}

// New returns a freshly created cache with all its internal structures initialized
func New() *Cache {
	cache := Cache{
		internalList: list.New(),
		lruList:      list.New(),
		hashMap:      make(map[string]*list.Element),
	}
	return &cache
}

// GetOrAdd only inserts the key value pair to Cache if there has not yet been a mapping for key. It
// first returns the already existing value associated with the key or otherwise the new value. The
// second return value is a boolean value which is true if the mapping has not yet been present.
func (c *Cache) GetOrAdd(key string, value interface{}, isInternal bool) (interface{}, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()
	e, ok := c.hashMap[key]
	if ok {
		if e == nil {
			log.Error("A list element returned by the hash map is nil. This should never occur!")
		}
		v := e.Value.(*entry)
		if v.internal {
			c.internalList.MoveToFront(e)
		} else {
			c.lruList.MoveToFront(e)
		}
		return v.value, false
	}
	if isInternal {
		e = c.internalList.PushFront(&entry{internal: true, key: key, value: value})
	} else {
		e = c.lruList.PushFront(&entry{internal: false, key: key, value: value})
	}
	c.hashMap[key] = e
	return value, true
}

// Get returns if the key is present the value associated with it from the map and true. Otherwise
// the value type's zero value and false is returned
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	v, ok := c.hashMap[key]
	if ok {
		e := v.Value.(*entry)
		if e.internal {
			c.internalList.MoveToFront(v)
		} else {
			c.lruList.MoveToFront(v)
		}
		return e.value, true
	}
	return nil, false
}

// GetAll returns all contained values. It does not affect lru list order.
func (c *Cache) GetAll() []interface{} {
	c.mux.RLock()
	defer c.mux.RUnlock()
	values := []interface{}{}
	for _, v := range c.hashMap {
		values = append(values, v.Value.(*entry).value)
	}
	return values
}

// Remove deletes the key value pair from the map.
// It returns the value and true if an element was deleted. Otherwise the value and false.
func (c *Cache) Remove(key string) (interface{}, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()
	e, ok := c.hashMap[key]
	if !ok {
		return nil, false
	}
	delete(c.hashMap, key)
	v := e.Value.(*entry)
	if v.internal {
		c.internalList.Remove(e)
	} else {
		c.lruList.Remove(e)
	}
	return v.value, true
}

// GetLeastRecentlyUsed returns the least recently used key value pair. It does not update the
// recentness of the element
func (c *Cache) GetLeastRecentlyUsed() (string, interface{}) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	e := c.lruList.Back()
	if e != nil {
		v := e.Value.(*entry)
		return v.key, v.value
	}
	return "", nil
}

// Len returns the number of elements in the cache
func (c *Cache) Len() int {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return len(c.hashMap)
}
