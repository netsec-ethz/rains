package set

import (
	"sync"

	"github.com/netsec-ethz/rains/internal/pkg/sections"
)

//Set contains a collection of data elements stored in a hash set. All exported methods manipulating the hash set in Set are concurrency safe.
type Set struct {
	mux       sync.RWMutex
	isDeleted bool //indicates that no further changes to data are allowed and that this Set is in the process of being deleted.
	data      map[string]sections.Hashable
}

//New creates a new data container
func New() *Set {
	return &Set{isDeleted: false, data: make(map[string]sections.Hashable)}
}

//Add adds item to the hash set. This method is concurrency safe.
//Add returns false if item could not be added to the hash set as it is in the process of being deleted.
func (set *Set) Add(item sections.Hashable) bool {
	set.mux.Lock()
	defer set.mux.Unlock()
	if set.isDeleted {
		return false
	}
	set.data[item.Hash()] = item
	return true
}

//Delete removes item from the hash set if it is contained. This method is concurrency safe.
//Returns true if item was contained
func (set *Set) Delete(item sections.Hashable) bool {
	set.mux.Lock()
	defer set.mux.Unlock()
	if _, ok := set.data[item.Hash()]; !set.isDeleted && ok {
		delete(set.data, item.Hash())
		return true
	}
	return false
}

//GetAll returns a slice of all elements contained in the hash set.
//If the hash set is in the process of being deleted GetAll return an empty slice
func (set *Set) GetAll() []sections.Hashable {
	set.mux.RLock()
	defer set.mux.RUnlock()
	if set.isDeleted {
		return []sections.Hashable{}
	}
	var data []sections.Hashable
	for _, item := range set.data {
		data = append(data, item)
	}
	return data
}

//GetAllAndDelete returns a slice of all elements contained in the hash set and sets the isDeleted flag such that no methods will access this hash set anymore in the future.
//If the hash set is already in the process of being deleted GetAllAndDelete return an empty slice.
func (set *Set) GetAllAndDelete() []sections.Hashable {
	set.mux.Lock()
	defer set.mux.Unlock()
	if set.isDeleted {
		return []sections.Hashable{}
	}
	var data []sections.Hashable
	for _, item := range set.data {
		data = append(data, item)
	}
	set.isDeleted = true
	return data
}

//Len returns the number of elements in the set.
func (set *Set) Len() int {
	set.mux.RLock()
	defer set.mux.RUnlock()
	if set.isDeleted {
		return 0
	}
	return len(set.data)
}
