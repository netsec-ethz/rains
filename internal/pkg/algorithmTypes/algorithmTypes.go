package algorithmTypes

//Signature specifies a signature algorithm type
type Signature int

const (
	Ed25519 Signature = iota + 1
	Ed448
	Ecdsa256
	Ecdsa384
)

//Hash specifies a hash algorithm type
type Hash int

const (
	NoHashAlgo Hash = iota
	Sha256
	Sha384
	Sha512
	Fnv64
	Murmur364
)
