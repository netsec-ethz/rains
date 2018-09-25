package rainslib

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash/fnv"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/utils/bitarray"
	"github.com/spaolacci/murmur3"
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
type DataStructureType int

const (
	BloomFilterType DataStructureType = iota + 1
)

//ModeOfOperationType enumerates mode of operation types for pshards
type ModeOfOperationType int

const (
	StandardOpType ModeOfOperationType = iota
	KirschMitzenmacher1
	KirschMitzenmacher2
)

//BloomFilter is a probabilistic datastructure for membership queries.
type BloomFilter struct {
	HashFamily       []HashAlgorithmType
	NofHashFunctions int
	ModeOfOperation  ModeOfOperationType
	Filter           bitarray.BitArray
}

//HasAssertion returns true if a might be part of the set represented by the bloom filter. It
//returns false if a is certainly not part of the set.
func (b BloomFilter) HasAssertion(a *AssertionSection) (bool, error) {
	switch b.ModeOfOperation {
	case StandardOpType:
		return b.hasAssertionStandard(a.BloomFilterEncoding())
	case KirschMitzenmacher1, KirschMitzenmacher2:
		return b.hasAssertionKM(a.BloomFilterEncoding())
	default:
		return false, errors.New("Unsupported mode of operation for a bloom filter")
	}
}

func (b BloomFilter) hasAssertionStandard(assertionEncoding string) (bool, error) {
	if len(b.HashFamily) != b.NofHashFunctions {
		log.Error("len(HashFamily) != nofHashFunctions", "len(HashFamily)", len(b.HashFamily),
			"NofHashFunctions", b.NofHashFunctions)
		return false, errors.New("len(HashFamily) != nofHashFunctions")
	}
	for _, id := range b.HashFamily {
		if val, err := b.Filter.GetBit(int(calcHash(id, assertionEncoding) % uint64(8*len(b.Filter)))); err != nil {
			return false, err
		} else if !val {
			return false, nil
		}
	}
	return true, nil
}

func (b BloomFilter) hasAssertionKM(assertionEncoding string) (bool, error) {
	hash1, hash2, err := b.getKMHashes(assertionEncoding)
	if err != nil {
		return false, err
	}
	for i := 0; i < b.NofHashFunctions; i++ {
		if val, err := b.Filter.GetBit(int((hash1 + uint64(i)*hash2) % uint64(8*len(b.Filter)))); err != nil {
			return false, err
		} else if !val {
			return false, nil
		}
	}
	return true, nil
}

//AddAssertion sets the corresponding bits to 1 in the bloom filter based on the hash family,
//number of hash functions used and mode of operation.
func (b BloomFilter) AddAssertion(a *AssertionSection) error {
	switch b.ModeOfOperation {
	case StandardOpType:
		return b.addAssertionStandard(a.BloomFilterEncoding())
	case KirschMitzenmacher1, KirschMitzenmacher2:
		return b.addAssertionKM(a.BloomFilterEncoding())
	default:
		return errors.New("Unsupported mode of operation for a bloom filter")
	}
}

func (b BloomFilter) addAssertionStandard(assertionEncoding string) error {
	if len(b.HashFamily) != b.NofHashFunctions {
		log.Error("len(HashFamily) != nofHashFunctions", "len(HashFamily)", len(b.HashFamily),
			"NofHashFunctions", b.NofHashFunctions)
		return errors.New("len(HashFamily) != nofHashFunctions")
	}
	for _, id := range b.HashFamily {
		if err := b.Filter.SetBit(int(calcHash(id, assertionEncoding) % uint64(8*len(b.Filter)))); err != nil {
			return err
		}
	}
	return nil
}

func (b BloomFilter) addAssertionKM(assertionEncoding string) error {
	hash1, hash2, err := b.getKMHashes(assertionEncoding)
	if err != nil {
		return err
	}
	for i := 0; i < b.NofHashFunctions; i++ {
		if err := b.Filter.SetBit(int((hash1 + uint64(i)*hash2) % uint64(8*len(b.Filter)))); err != nil {
			return err
		}
	}
	return nil
}

func (b BloomFilter) getKMHashes(assertionEncoding string) (uint64, uint64, error) {
	if len(b.HashFamily) == 1 {
		//FIXME CFE currently only works for hash functions returning 64 bit value
		hash := calcHash(b.HashFamily[0], assertionEncoding)
		return uint64(int(hash)), uint64(int(hash >> 32)), nil //int64(int()) truncate upper 32 bits
	} else if len(b.HashFamily) != 2 {
		return calcHash(b.HashFamily[0], assertionEncoding), calcHash(b.HashFamily[1], assertionEncoding), nil
	} else {
		log.Error("len(HashFamily) should be 1 or 2", "len(HashFamily)", len(b.HashFamily),
			"NofHashFunctions", b.NofHashFunctions)
		return 0, 0, errors.New("len(HashFamily) should be 1 or 2")
	}
}

func calcHash(hashType HashAlgorithmType, encoding string) uint64 {
	switch hashType {
	case Sha256:
		hash := sha256.Sum256([]byte(encoding))
		return binary.BigEndian.Uint64(hash[:])
	case Sha384:
		hash := sha512.Sum384([]byte(encoding))
		return binary.BigEndian.Uint64(hash[:])
	case Sha512:
		hash := sha512.Sum512([]byte(encoding))
		return binary.BigEndian.Uint64(hash[:])
	case Fnv64:
		hash := fnv.New64()
		return hash.Sum64()
	case Murmur364:
		return murmur3.Sum64([]byte(encoding))
	default:
		log.Error("Unsupported hash algorithm type")
		return 0
	}
}

//CompareTo compares two BloomFilters and returns 0 if they are equal, 1 if b is greater than
//bloomFilter and -1 if b is smaller than bloomFilter
func (b BloomFilter) CompareTo(bloomFilter BloomFilter) int {
	//FIXME CFE remove this function and use cbor encoded string to compare
	if b.NofHashFunctions < bloomFilter.NofHashFunctions {
		return -1
	} else if b.NofHashFunctions > bloomFilter.NofHashFunctions {
		return 1
	} else if b.ModeOfOperation < bloomFilter.ModeOfOperation {
		return -1
	} else if b.ModeOfOperation > bloomFilter.ModeOfOperation {
		return 1
	} else if len(b.Filter) < len(bloomFilter.Filter) {
		return -1
	} else if len(b.Filter) < len(bloomFilter.Filter) {
		return 1
	}
	return bytes.Compare(b.Filter, bloomFilter.Filter)
}
