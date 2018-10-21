package algorithmTypes

//Signature specifies a signature algorithm type
type Signature int

const (
	Ed25519 Signature = iota + 1
	Ed448
	Ecdsa256
	Ecdsa384
)

func (s Signature) String() string {
	switch s {
	case Ed25519:
		return "ed25519"
	case Ed448:
		return "Ed448"
	case Ecdsa256:
		return "Ecdsa256"
	case Ecdsa384:
		return "Ecdsa384"
	default:
		return "Unknown SignatureType"
	}
}

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

func (h Hash) String() string {
	switch h {
	case NoHashAlgo:
		return "noHashAlgo"
	case Sha256:
		return "sha256"
	case Sha384:
		return "sha384"
	case Sha512:
		return "sha512"
	case Fnv64:
		return "fnv64"
	case Murmur364:
		return "murmur364"
	default:
		return "Unknown HashType"
	}
}
