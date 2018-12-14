package section

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash/fnv"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"golang.org/x/crypto/sha3"
)

//ModeOfOperationType enumerates mode of operation connection for pshards
type BloomFilterAlgo int

const (
	BloomKM12 BloomFilterAlgo = iota
	BloomKM16
	BloomKM20
	BloomKM24
)

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

//BloomFilter is a probabilistic datastructure for membership queries.
type BloomFilter struct {
	Algorithm BloomFilterAlgo
	Hash      algorithmTypes.Hash
	Filter    bitarray.BitArray
}

// UnmarshalArray takes in a CBOR decoded array and populates the object.
func (b *BloomFilter) UnmarshalArray(in []interface{}) error {
	b.Algorithm = BloomFilterAlgo(int(in[0].(int)))
	b.Hash = algorithmTypes.Hash(in[1].(int))
	b.Filter = bitarray.BitArray(in[2].([]byte))
	return nil
}

// MarshalCBOR implements a CBORMarshaler.
func (b BloomFilter) MarshalCBOR(w *cbor.CBORWriter) error {
	return w.WriteArray([]interface{}{b.Algorithm, b.Hash, []byte(b.Filter)})
}

//HasAssertion returns true if a might be part of the set represented by the bloom filter. It
//returns false if a is certainly not part of the set.
func (b BloomFilter) HasAssertion(a *Assertion) (bool, error) {
	hash1, hash2, err := b.getKMHashes(a.BloomFilterEncoding())
	if err != nil {
		return false, err
	}
	for i := 0; i < b.Algorithm.NumberOfHashes(); i++ {
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
func (b BloomFilter) AddAssertion(a *Assertion) error {
	hash1, hash2, err := b.getKMHashes(a.BloomFilterEncoding())
	if err != nil {
		return err
	}
	for i := 0; i < b.Algorithm.NumberOfHashes(); i++ {
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

func calcHash(hashType algorithmTypes.Hash, encoding string) uint64 {
	switch hashType {
	case algorithmTypes.Sha256:
		hash := sha256.Sum256([]byte(encoding))
		return binary.BigEndian.Uint64(hash[:])
	case algorithmTypes.Sha384:
		hash := sha512.Sum384([]byte(encoding))
		return binary.BigEndian.Uint64(hash[:])
	case algorithmTypes.Sha512:
		hash := sha512.Sum512([]byte(encoding))
		return binary.BigEndian.Uint64(hash[:])
	case algorithmTypes.Shake256:
		hash := make([]byte, 64)
		sha3.ShakeSum256(hash, []byte(encoding))
		return binary.BigEndian.Uint64(hash[:])
	case algorithmTypes.Fnv64:
		hash := fnv.New64()
		return binary.BigEndian.Uint64(hash.Sum([]byte(encoding))[:])
	case algorithmTypes.Fnv128:
		hash := fnv.New128()
		return binary.BigEndian.Uint64(hash.Sum([]byte(encoding))[:])
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
