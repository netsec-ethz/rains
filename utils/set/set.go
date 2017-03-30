package set

import (
	"sync"
)

//Set contains a collection of data elements stored in a hash set. All exported methods manipulating the hash set in Set are concurrency safe.
type Set struct {
	mux       sync.RWMutex
	isDeleted bool //indicates that no further changes to data are allowed and that this Set is in the process of being deleted.
	data      map[interface{}]bool
}

//New creates a new data container
func New() *Set {
	return &Set{isDeleted: false, data: make(map[interface{}]bool)}
}

//Add adds item to the hash set. This method is concurrency safe.
//Add returns false if item could not be added to the hash set as it is in the process of being deleted.
func (set *Set) Add(item interface{}) bool {
	set.mux.Lock()
	defer set.mux.Unlock()
	if set.isDeleted {
		return false
	}
	set.data[item] = true
	return true
}

//Delete removes item from the hash set if it is contained. This method is concurrency safe.
func (set *Set) Delete(item interface{}) {
	set.mux.Lock()
	defer set.mux.Unlock()
	if !set.isDeleted {
		delete(set.data, item)
	}
}

//GetAll returns a slice of all elements contained in the hash set.
//If the hash set is in the process of being deleted GetAll return an empty slice
func (set *Set) GetAll() []interface{} {
	set.mux.RLock()
	defer set.mux.RUnlock()
	if set.isDeleted {
		return []interface{}{}
	}
	var data []interface{}
	for item := range set.data {
		data = append(data, item)
	}
	return data
}

//GetAllAndDelete returns a slice of all elements contained in the hash set and sets the isDeleted flag such that no methods will access this hash set anymore in the future.
//If the hash set is already in the process of being deleted GetAllAndDelete return an empty slice.
func (set *Set) GetAllAndDelete() []interface{} {
	set.mux.Lock()
	defer set.mux.Unlock()
	if set.isDeleted {
		return []interface{}{}
	}
	var data []interface{}
	for item := range set.data {
		data = append(data, item)
	}
	set.isDeleted = true
	return data
}
