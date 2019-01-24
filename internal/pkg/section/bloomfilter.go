package section

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"

	cbor "github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"golang.org/x/crypto/sha3"
)

//BloomFilter is a probabilistic datastructure for membership queries.
type BloomFilter struct {
	Algorithm BloomFilterAlgo
	Hash      algorithmTypes.Hash
	Filter    bitarray.BitArray
}

// UnmarshalArray takes in a CBOR decoded array and populates the object.
func (b *BloomFilter) UnmarshalArray(in []interface{}) error {
	if len(in) != 3 {
		return fmt.Errorf("cbor array encoding of bloom filter is not of length 3. actual=%d", len(in))
	}
	algo, ok := in[0].(int)
	if !ok {
		return errors.New("cbor encoding of the algorithm should be an int")
	}
	b.Algorithm = BloomFilterAlgo(algo)
	hash, ok := in[1].(int)
	if !ok {
		return errors.New("cbor encoding of the hash should be an int")
	}
	b.Hash = algorithmTypes.Hash(hash)
	filter, ok := in[2].([]byte)
	if !ok {
		return errors.New("cbor encoding of the filter should be an byte array")
	}
	b.Filter = bitarray.BitArray(filter)
	return nil
}

// MarshalCBOR implements a CBORMarshaler.
func (b BloomFilter) MarshalCBOR(w *cbor.CBORWriter) error {
	return w.WriteArray([]interface{}{b.Algorithm, b.Hash, []byte(b.Filter)})
}

//Contains returns true if a might be part of the set represented by the bloom filter. It
//returns false if a is certainly not part of the set.
func (b BloomFilter) Contains(name, zone, context string, t object.Type) (bool, error) {
	hash1, hash2, err := calcHash(b.Hash, encoding(name, zone, context, t))
	if err != nil {
		return false, err
	}
	for i := 1; i <= b.Algorithm.NumberOfHashes(); i++ {
		if val, err := b.Filter.GetBit(int((hash1 + uint64(i)*hash2) % uint64(8*len(b.Filter)))); err != nil {
			return false, err
		} else if !val {
			return false, nil
		}
	}
	return true, nil
}

//Add sets the corresponding bits to 1 in the bloom filter based on BloomFilterAlgo and
//the hash function defined in b.
func (b BloomFilter) Add(name, zone, context string, t object.Type) error {
	hash1, hash2, err := calcHash(b.Hash, encoding(name, zone, context, t))
	if err != nil {
		return err
	}
	for i := 1; i <= b.Algorithm.NumberOfHashes(); i++ {
		if err := b.Filter.SetBit(int((hash1 + uint64(i)*hash2) % uint64(8*len(b.Filter)))); err != nil {
			return err
		}
	}
	return nil
}

func encoding(name, zone, context string, t object.Type) []byte {
	encoding := new(bytes.Buffer)
	writer := cbor.NewCBORWriter(encoding)
	writer.WriteArray([]interface{}{name, zone, context, t})
	return encoding.Bytes()
}

func calcHash(hashType algorithmTypes.Hash, encoding []byte) (uint64, uint64, error) {
	switch hashType {
	case algorithmTypes.Shake256:
		hash := make([]byte, 64)
		sha3.ShakeSum256(hash, encoding)
		val := binary.BigEndian.Uint64(hash[:])
		return uint64(int(val)), uint64(int(val >> 32)), nil //int64(int()) truncate upper 32 bits
	case algorithmTypes.Fnv64:
		hash := fnv.New64()
		hash.Write(encoding)
		val := hash.Sum64()
		return uint64(int(val)), uint64(int(val >> 32)), nil //int64(int()) truncate upper 32 bits
	case algorithmTypes.Fnv128:
		hash := fnv.New128()
		hash.Write(encoding)
		val := hash.Sum([]byte{})
		return binary.BigEndian.Uint64(val[:8]), binary.BigEndian.Uint64(val[8:16]), nil
	default:
		return 0, 0, errors.New("Unsupported hash algorithm type for bloom filter")
	}
}

//CompareTo compares two BloomFilters and returns 0 if they are equal, 1 if b is greater than
//bloomFilter and -1 if b is smaller than bloomFilter
func (b BloomFilter) CompareTo(bloomFilter BloomFilter) int {
	if b.Algorithm < bloomFilter.Algorithm {
		return -1
	} else if b.Algorithm > bloomFilter.Algorithm {
		return 1
	} else if b.Hash < bloomFilter.Hash {
		return -1
	} else if b.Hash > bloomFilter.Hash {
		return 1
	} else if len(b.Filter) < len(bloomFilter.Filter) {
		return -1
	} else if len(b.Filter) < len(bloomFilter.Filter) {
		return 1
	}
	return bytes.Compare(b.Filter, bloomFilter.Filter)
}

//BloomFilterAlgo enumerates several ways how to add an assertion to the bloom
//filter.
type BloomFilterAlgo int

//go:generate stringer -type=BloomFilterAlgo
const (
	BloomKM12 BloomFilterAlgo = iota + 1
	BloomKM16
	BloomKM20
	BloomKM24
)

//NumberOfHashes determines how many bits in the bloom filter are set in an
//addition and checked on a lookup.
func (b BloomFilterAlgo) NumberOfHashes() int {
	switch b {
	case BloomKM12:
		return 12
	case BloomKM16:
		return 16
	case BloomKM20:
		return 20
	case BloomKM24:
		return 24
	default:
		return -1
	}
}
