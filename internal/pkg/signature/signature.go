package signature

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

// UnmarshalArray takes in a CBOR decoded array and populates Sig.
func (sig *Sig) UnmarshalArray(in []interface{}) error {
	if len(in) != 6 {
		return fmt.Errorf("expected 6 items in input array but got %d", len(in))
	}
	algo, ok := in[0].(int)
	if !ok {
		return errors.New("cbor encoding of the algorithm should be an int")
	}
	sig.PublicKeyID.Algorithm = algorithmTypes.Signature(algo)
	keySpace, ok := in[1].(int)
	if !ok {
		return errors.New("cbor encoding of the key space should be an int")
	}
	sig.PublicKeyID.KeySpace = keys.KeySpaceID(keySpace)
	sig.PublicKeyID.KeyPhase, ok = in[2].(int)
	if !ok {
		return errors.New("cbor encoding of the key phase should be an int")
	}
	validSince, ok := in[3].(int)
	if !ok {
		return errors.New("cbor encoding of the validSince should be an int")
	}
	sig.ValidSince = int64(validSince)
	validUntil, ok := in[4].(int)
	if !ok {
		return errors.New("cbor encoding of the validUntil should be an int")
	}
	sig.ValidUntil = int64(validUntil)
	data, ok := in[5].([]byte)
	if !ok {
		return errors.New("cbor encoding of the data should be a byte array")
	}
	sig.Data = data
	return nil
}

// MarshalCBOR implements a CBORMarshaler.
func (sig Sig) MarshalCBOR(w *cbor.CBORWriter) error {
	res := []interface{}{int(sig.Algorithm), int(sig.KeySpace), sig.KeyPhase, sig.ValidSince, sig.ValidUntil, []byte{}}
	if data, ok := sig.Data.([]byte); ok && len(data) > 0 && !sig.sign {
		res[5] = sig.Data
	}
	return w.WriteArray(res)
}

//MetaData contains meta data of the signature
type MetaData struct {
	keys.PublicKeyID
	//ValidSince defines the time from which on this signature is valid. ValidSince is represented as seconds since the UNIX epoch UTC.
	ValidSince int64
	//ValidUntil defines the time after which this signature is not valid anymore. ValidUntil is represented as seconds since the UNIX epoch UTC.
	ValidUntil int64
}

//Sig contains meta data of the signature and the signature data itself.
type Sig struct {
	keys.PublicKeyID
	//ValidSince defines the time from which on this signature is valid. ValidSince is represented as seconds since the UNIX epoch UTC.
	ValidSince int64
	//ValidUntil defines the time after which this signature is not valid anymore. ValidUntil is represented as seconds since the UNIX epoch UTC.
	ValidUntil int64
	//Data holds the signature data
	Data interface{}
	sign bool //set to true before signing and false afterwards
}

//MetaData returns the signatures metaData
func (sig Sig) MetaData() MetaData {
	return MetaData{
		PublicKeyID: sig.PublicKeyID,
		ValidSince:  sig.ValidSince,
		ValidUntil:  sig.ValidUntil,
	}
}

//String implements Stringer interface
func (sig Sig) String() string {
	data := "notYetImplementedInStringMethod"
	if sig.Algorithm == algorithmTypes.Ed25519 {
		if sig.Data == nil {
			data = "nil"
		} else {
			data = hex.EncodeToString(sig.Data.([]byte))
		}
	}
	return fmt.Sprintf("{KS=%d AT=%d VS=%d VU=%d KP=%d data=%s}",
		sig.KeySpace, sig.Algorithm, sig.ValidSince, sig.ValidUntil, sig.KeyPhase, data)
}

//CompareTo compares two signature objects and returns 0 if they are equal, 1 if sig is greater than
//s and -1 if sig is smaller than s
func (sig Sig) CompareTo(s Sig) int {
	if sig.Algorithm < s.Algorithm {
		return -1
	} else if sig.Algorithm > s.Algorithm {
		return 1
	} else if sig.KeySpace < s.KeySpace {
		return -1
	} else if sig.KeySpace > s.KeySpace {
		return 1
	} else if sig.KeyPhase < s.KeyPhase {
		return -1
	} else if sig.KeyPhase > s.KeyPhase {
		return 1
	} else if sig.ValidSince < s.ValidSince {
		return -1
	} else if sig.ValidSince > s.ValidSince {
		return 1
	} else if sig.ValidUntil < s.ValidUntil {
		return -1
	} else if sig.ValidUntil > s.ValidUntil {
		return 1
	}
	switch sig.Algorithm {
	case algorithmTypes.Ed25519:
		return bytes.Compare(sig.Data.([]byte), s.Data.([]byte))
	default:
		log.Warn("Unsupported algo type", "type", fmt.Sprintf("%T", sig.Algorithm))
	}
	return 0
}

//SignData adds signature meta data to encoding. It then signs the encoding with privateKey and updates sig.Data field with the generated signature
//In case of an error an error is returned indicating the cause, otherwise nil is returned
func (sig *Sig) SignData(privateKey interface{}, encoding []byte) error {
	if privateKey == nil {
		return errors.New("privateKey is nil")
	}
	sigEncoding := new(bytes.Buffer)
	if err := sig.MarshalCBOR(cbor.NewCBORWriter(sigEncoding)); err != nil {
		return err
	}
	encoding = append(encoding, sigEncoding.Bytes()...)
	switch sig.Algorithm {
	case algorithmTypes.Ed25519:
		if pkey, ok := privateKey.(ed25519.PrivateKey); ok {
			log.Debug("Sign data", "signature", sig, "privateKey", hex.EncodeToString(privateKey.(ed25519.PrivateKey)), "encoding", encoding)
			sig.Data = ed25519.Sign(pkey, encoding)
			return nil
		}
		return errors.New("could not assert type ed25519.PrivateKey")
	default:
		return fmt.Errorf("signature algorithm type not supported: %s", sig.Algorithm)
	}
}

//VerifySignature adds signature meta data to the encoding. It then signs the encoding with privateKey and compares the resulting signature with the sig.Data.
//Returns true if there exist signatures and they are identical
func (sig *Sig) VerifySignature(publicKey interface{}, encoding []byte) bool {
	if sig.Data == nil {
		log.Warn("sig does not contain signature data", "sig", sig)
		return false
	}
	if publicKey == nil {
		log.Warn("PublicKey is nil")
		return false
	}
	//sigData := sig.Data
	//sig.Data = []byte{}
	sig.sign = true
	sigEncoding := new(bytes.Buffer)
	if err := sig.MarshalCBOR(cbor.NewCBORWriter(sigEncoding)); err != nil {
		log.Error("Was not able to cbor encode signature")
		return false
	}
	encoding = append(encoding, sigEncoding.Bytes()...)
	switch sig.Algorithm {
	case algorithmTypes.Ed25519:
		if pkey, ok := publicKey.(ed25519.PublicKey); ok {
			ok = ed25519.Verify(pkey, encoding, sig.Data.([]byte))
			sig.sign = false
			return ok
		}
		log.Warn("Could not assert type ed25519.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	default:
		log.Warn("Sig algorithm type not supported", "type", sig.Algorithm)
	}
	return false
}
