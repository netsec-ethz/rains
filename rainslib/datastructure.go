package rainslib

import (
	"bytes"

	log "github.com/inconshreveable/log15"
)

//DataStructure contains information about a datastructure. The Type defines the object in Data.
type DataStructure struct {
	Type DataStructureType
	Data interface{}
}

//CompareTo compares two DataStructure and returns 0 if they are equal, 1 if s is greater than
//dataStructure and -1 if d is smaller than dataStructure
func (d DataStructure) CompareTo(ds DataStructure) int {
	if d.Type < ds.Type {
		return -1
	} else if d.Type > ds.Type {
		return 1
	}
	switch d.Type {
	case BloomFilterType:
		return d.Data.(BloomFilter).CompareTo(ds.Data.(BloomFilter))
	default:
		log.Warn("Data structure type does not exist")
	}
	return 0
}

//DataStructureType enumerates data structure types for pshards
//go:generate jsonenums -type=DataStructureType
type DataStructureType int

//run 'go generate' in this directory if a new datastructureType is added [source https://github.com/campoy/jsonenums]
const (
	BloomFilterType DataStructureType = iota + 1
)

//BloomFilter is a probabilistic datastructure for membership queries.
type BloomFilter struct {
	HashFamily       HashAlgorithmType
	NofHashfunctions int
	Filter           []byte
}

//CompareTo compares two BloomFilters and returns 0 if they are equal, 1 if b is greater than
//bloomFilter and -1 if b is smaller than bloomFilter
func (b BloomFilter) CompareTo(bloomFilter BloomFilter) int {
	if b.HashFamily < bloomFilter.HashFamily {
		return -1
	} else if b.HashFamily > bloomFilter.HashFamily {
		return 1
	} else if b.NofHashfunctions < bloomFilter.NofHashfunctions {
		return -1
	} else if b.NofHashfunctions > bloomFilter.NofHashfunctions {
		return 1
	} else if len(b.Filter) < len(bloomFilter.Filter) {
		return -1
	} else if len(b.Filter) < len(bloomFilter.Filter) {
		return 1
	}
	return bytes.Compare(b.Filter, bloomFilter.Filter)
}
