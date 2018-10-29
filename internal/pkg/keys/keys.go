package keys

import (
	"bytes"
	"encoding/hex"
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"golang.org/x/crypto/ed25519"
)

//PublicKeyID contains all necessary information to distinguish different public keys from the same
//authority
type PublicKeyID struct {
	//Algorithm determines the signature algorithm to be used for signing and verification
	Algorithm algorithmTypes.Signature
	//KeySpace is an identifier of a key space
	KeySpace KeySpaceID
	//KeyPhase defines the keyPhase in which this public key is valid
	KeyPhase int
}

func (p PublicKeyID) String() string {
	return fmt.Sprintf("AT=%s KS=%s KP=%d", p.Algorithm, p.KeySpace, p.KeyPhase)
}

//Hash returns a string containing all information uniquely identifying a public key ID.
func (p PublicKeyID) Hash() string {
	return fmt.Sprintf("%d,%d,%d", p.Algorithm, p.KeySpace, p.KeyPhase)
}

//PublicKey contains information about a public key
type PublicKey struct {
	PublicKeyID
	ValidSince int64
	ValidUntil int64
	Key        interface{}
}

//CompareTo compares two publicKey objects and returns 0 if they are equal, 1 if p is greater than pkey and -1 if p is smaller than pkey
func (p PublicKey) CompareTo(pkey PublicKey) int {
	if p.Algorithm < pkey.Algorithm {
		return -1
	} else if p.Algorithm > pkey.Algorithm {
		return 1
	} else if p.KeySpace < pkey.KeySpace {
		return -1
	} else if p.KeySpace > pkey.KeySpace {
		return 1
	} else if p.ValidSince < pkey.ValidSince {
		return -1
	} else if p.ValidSince > pkey.ValidSince {
		return 1
	} else if p.ValidUntil < pkey.ValidUntil {
		return -1
	} else if p.ValidUntil > pkey.ValidUntil {
		return 1
	} else if p.KeyPhase < pkey.KeyPhase {
		return -1
	} else if p.KeyPhase > pkey.KeyPhase {
		return 1
	}
	switch k1 := p.Key.(type) {
	case ed25519.PublicKey:
		if k2, ok := pkey.Key.(ed25519.PublicKey); ok {
			return bytes.Compare(k1, k2)
		}
		log.Error("PublicKey.Key Type does not match algorithmIdType", "algoType", pkey.Algorithm, "KeyType", fmt.Sprintf("%T", pkey.Key))
	default:
		log.Warn("Unsupported public key type", "type", fmt.Sprintf("%T", p.Key))
	}
	return 0
}

//String implements Stringer interface
func (p PublicKey) String() string {
	keyString := ""
	switch k1 := p.Key.(type) {
	case ed25519.PublicKey:
		keyString = hex.EncodeToString(k1)
	default:
		log.Warn("Unsupported public key type", "type", fmt.Sprintf("%T", p.Key))
	}
	return fmt.Sprintf("{%s VS=%d VU=%d data=%s}", p.PublicKeyID, p.ValidSince, p.ValidUntil, keyString)
}

//Hash returns a string containing all information uniquely identifying a public key.
func (p PublicKey) Hash() string {
	keyString := ""
	switch k1 := p.Key.(type) {
	case ed25519.PublicKey:
		keyString = hex.EncodeToString(k1)
	default:
		log.Warn("Unsupported public key type", "type", fmt.Sprintf("%T", p.Key))
	}
	return fmt.Sprintf("%s,%d,%d,%s", p.PublicKeyID.Hash(), p.ValidSince, p.ValidUntil, keyString)
}

//PrivateKey contains information about a private key
type PrivateKey struct {
	PublicKeyID
	Key interface{}
}

//String implements Stringer interface
func (p PrivateKey) String() string {
	keyString := ""
	switch k1 := p.Key.(type) {
	case ed25519.PrivateKey:
		keyString = hex.EncodeToString(k1)
	default:
		log.Warn("Unsupported private key type", "type", fmt.Sprintf("%T", p.Key))
	}
	return fmt.Sprintf("{%s data=%s}", p.PublicKeyID, keyString)
}

//KeySpaceID identifies a key space
type KeySpaceID int

const (
	RainsKeySpace KeySpaceID = 0
)

func (k KeySpaceID) String() string {
	switch k {
	case RainsKeySpace:
		return "rains"
	default:
		return "Unknown SignatureType"
	}
}
