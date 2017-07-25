package safeHashMap

import "sync"

//Map is a concurrency safe hash map
type Map struct {
	hashMap map[string]interface{}
	mux     sync.RWMutex
}

//New returns a new concurrency safe hash map
func New() *Map {
	return &Map{hashMap: make(map[string]interface{})}
}

//Add inserts the key value pair to the map. If there is already a mapping it will be overwritten by
//the new value. It returns true if there was not yet a mapping.
func (m *Map) Add(key string, value interface{}) bool {
	m.mux.Lock()
	defer m.mux.Unlock()
	size := len(m.hashMap)
	m.hashMap[key] = value
	return len(m.hashMap) > size
}

//GetOrAdd only inserts the key value pair to Map if there has not yet been a mapping for key. It
//first returns the already existing value associated with the key or otherwise the new value. The
//second return value is a boolean value which is true if the mapping has not yet been present.
func (m *Map) GetOrAdd(key string, value interface{}) (interface{}, bool) {
	m.mux.Lock()
	defer m.mux.Unlock()
	v, ok := m.hashMap[key]
	if ok {
		return v, false
	}
	m.hashMap[key] = value
	return value, true
}

//Get returns if the key is present the value associated with it from the map and true. Otherwise
//the value type's zero value and false is returned
func (m *Map) Get(key string) (interface{}, bool) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	v, ok := m.hashMap[key]
	return v, ok
}

//GetAll returns all contained values
func (m *Map) GetAll() []interface{} {
	m.mux.RLock()
	defer m.mux.RUnlock()
	values := []interface{}{}
	for _, v := range m.hashMap {
		values = append(values, v)
	}
	return values
}

//GetAllKeys returns all keys
func (m *Map) GetAllKeys() []string {
	m.mux.RLock()
	defer m.mux.RUnlock()
	keys := []string{}
	for k := range m.hashMap {
		keys = append(keys, k)
	}
	return keys
}

//Remove deletes the key value pair from the map.
//It returns the value and true if an element was deleted. Otherwise nil and false
func (m *Map) Remove(key string) (interface{}, bool) {
	m.mux.Lock()
	defer m.mux.Unlock()
	size := len(m.hashMap)
	value := m.hashMap[key]
	delete(m.hashMap, key)
	return value, len(m.hashMap) < size
}

//Len returns the number of elements in the map
func (m *Map) Len() int {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return len(m.hashMap)
}
