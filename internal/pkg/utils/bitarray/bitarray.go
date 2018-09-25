package bitarray

import "errors"

//Bitarray datastructure
type BitArray []byte

//SetBit sets the ith bit. Returns an error if i is out of bound
func (b BitArray) SetBit(i int) error {
	block := i / 8
	if block >= len(b) {
		return errors.New("i out of bound")
	}
	b[block] |= getOffset(i % 8)
	return nil
}

//GetBit gets the ith bit. Returns true if bit is set; or an error if i is out of bound
func (b BitArray) GetBit(i int) (bool, error) {
	block := i / 8
	if block >= len(b) {
		return false, errors.New("i out of bound")
	}
	return (b[block] & getOffset(i%8)) != 0, nil
}

//getOffset returns an uint8 bit mask where pos is set to 1. 0 is returned when pos is larger than 7
//or negative.
func getOffset(pos int) uint8 {
	if pos == 0 {
		return 1
	} else if pos == 1 {
		return 2
	} else if pos == 2 {
		return 4
	} else if pos == 3 {
		return 8
	} else if pos == 4 {
		return 16
	} else if pos == 5 {
		return 32
	} else if pos == 6 {
		return 64
	} else if pos == 7 {
		return 128
	}
	return 0
}
