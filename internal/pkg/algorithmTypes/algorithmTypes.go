package algorithmTypes

//Signature specifies a signature algorithm type
type Signature int

//go:generate stringer -type=Signature
const (
	Ed25519 Signature = iota + 1
	Ed448
)

//Hash specifies a hash algorithm type
type Hash int

//go:generate stringer -type=Hash
const (
	NoHashAlgo Hash = iota
	Sha256
	Sha384
	Sha512
	Shake256
	Fnv64
	Fnv128
)
