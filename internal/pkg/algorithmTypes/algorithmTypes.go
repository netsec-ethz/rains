package algorithmTypes

//SignatureAlgorithmType specifies a signature algorithm type
type SignatureAlgorithmType int

const (
	Ed25519 SignatureAlgorithmType = iota + 1
	Ed448
	Ecdsa256
	Ecdsa384
)

//HashAlgorithmType specifies a hash algorithm type
type HashAlgorithmType int

const (
	NoHashAlgo HashAlgorithmType = iota
	Sha256
	Sha384
	Sha512
	Fnv64
	Murmur364
)
