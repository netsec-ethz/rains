package algorithmTypes

import (
	"fmt"
	"strconv"
)

// Signature specifies a signature algorithm type
type Signature int

//go:generate stringer -type=Signature
//go:generate jsonenums -type=Signature
const (
	Ed25519 Signature = iota + 1
	Ed448
)

// AtoSig returns a signature algorithm type based on common string representation thereof.
func AtoSig(str string) (Signature, error) {
	switch str {
	case Ed25519.String(), "ed25519", "ED25519", strconv.Itoa(int(Ed25519)):
		return Ed25519, nil
	case Ed448.String(), "ed448", "ED448", strconv.Itoa(int(Ed448)):
		return Ed448, nil
	}
	return Signature(-1), fmt.Errorf("%s is not a signature algorithm type", str)
}

// Hash specifies a hash algorithm type
type Hash int

//go:generate stringer -type=Hash
//go:generate jsonenums -type=Hash
const (
	NoHashAlgo Hash = iota
	Sha256
	Sha384
	Sha512
	Shake256
	Fnv64
	Fnv128
)
