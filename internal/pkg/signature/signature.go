package signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

//MetaData contains meta data of the signature
type MetaData struct {
	keys.PublicKeyID
	//ValidSince defines the time from which on this signature is valid. ValidSince is represented as seconds since the UNIX epoch UTC.
	ValidSince int64
	//ValidUntil defines the time after which this signature is not valid anymore. ValidUntil is represented as seconds since the UNIX epoch UTC.
	ValidUntil int64
}

func (sig MetaData) String() string {
	return fmt.Sprintf("%d %d %d %d %d",
		sig.KeySpace, sig.Algorithm, sig.ValidSince, sig.ValidUntil, sig.KeyPhase)
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
}

// UnmarshalArray takes in a CBOR decoded aray and populates Sig.
func (sig *Sig) UnmarshalArray(in []interface{}) error {
	if len(in) < 6 {
		return fmt.Errorf("expected at least 5 items in input array but got %d", len(in))
	}
	if in[0] != uint64(1) {
		return fmt.Errorf("only algorithm ED25519 is supported presently, but got: %d", in[0])
	}
	sig.PublicKeyID.Algorithm = algorithmTypes.Ed25519
	sig.PublicKeyID.KeyPhase = int(in[1].(uint64))
	sig.PublicKeyID.KeySpace = keys.KeySpaceID(in[2].(uint64))
	sig.ValidSince = int64(in[3].(uint64))
	sig.ValidUntil = int64(in[4].(uint64))
	sig.Data = in[5]
	return nil
}

// MarshalCBOR implements a CBORMarshaler.
func (sig Sig) MarshalCBOR(w cbor.Writer) error {
	res := []interface{}{1, // FIXME: Hardcoded ED25519: there is no way to know what this is yet.
		int(sig.KeySpace), sig.KeyPhase, sig.ValidSince, sig.ValidUntil, []byte{}}
	if data, ok := sig.Data.([]byte); ok && len(data) > 0 {
		res[5] = sig.Data
	}
	return w.WriteArray(res)
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

//SignData adds signature meta data to encoding. It then signs the encoding with privateKey and updates sig.Data field with the generated signature
//In case of an error an error is returned indicating the cause, otherwise nil is returned
func (sig *Sig) SignData(privateKey interface{}, encoding []byte) error {
	if privateKey == nil {
		log.Warn("PrivateKey is nil")
		return errors.New("privateKey is nil")
	}
	sigEncoding := new(bytes.Buffer)
	log.Info(sig.String())
	if err := sig.MarshalCBOR(cbor.NewWriter(sigEncoding)); err != nil {
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
		log.Warn("Could not assert type ed25519.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
		return errors.New("could not assert type ed25519.PrivateKey")
	case algorithmTypes.Ed448:
		return errors.New("ed448 not yet supported in SignData()")
	case algorithmTypes.Ecdsa256:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha256.Sum256(encoding)
			r, s, err := ecdsa.Sign(rand.Reader, pkey, hash[:])
			if err != nil {
				log.Warn("Could not sign data", "error", err)
				return err
			}
			sig.Data = []*big.Int{r, s}
			return nil
		}
		log.Warn("Could not assert type ecdsa.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
		return errors.New("could not assert type ecdsa.PrivateKey")
	case algorithmTypes.Ecdsa384:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha512.Sum384(encoding)
			r, s, err := ecdsa.Sign(rand.Reader, pkey, hash[:])
			if err != nil {
				log.Warn("Could not sign data", "error", err)
				return err
			}
			sig.Data = []*big.Int{r, s}
			return nil
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
		return errors.New("could not assert type ecdsa.PrivateKey")
	default:
		log.Warn("Sig algorithm type not supported", "type", sig.Algorithm)
		return errors.New("signature algorithm type not supported")
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
	sigData := sig.Data
	sig.Data = []byte{}
	sigEncoding := new(bytes.Buffer)
	if err := sig.MarshalCBOR(cbor.NewWriter(sigEncoding)); err != nil {
		log.Error("Was not able to cbor encode signature")
		return false
	}
	encoding = append(encoding, sigEncoding.Bytes()...)
	switch sig.Algorithm {
	case algorithmTypes.Ed25519:
		if pkey, ok := publicKey.(ed25519.PublicKey); ok {
			return ed25519.Verify(pkey, encoding, sigData.([]byte))
		}
		log.Warn("Could not assert type ed25519.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	case algorithmTypes.Ed448:
		log.Warn("Ed448 not yet Supported!")
	case algorithmTypes.Ecdsa256:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := sigData.([]*big.Int); ok && len(sig) == 2 {
				hash := sha256.Sum256(encoding)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not assert type []*big.Int", "signatureDataType", fmt.Sprintf("%T", sig.Data))
			return false
		}
		log.Warn("Could not assert type ecdsa.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	case algorithmTypes.Ecdsa384:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := sigData.([]*big.Int); ok && len(sig) == 2 {
				hash := sha512.Sum384(encoding)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not assert type []*big.Int", "signature", sig.Data)
			return false
		}
		log.Warn("Could not assert type ecdsa.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	default:
		log.Warn("Sig algorithm type not supported", "type", sig.Algorithm)
	}
	return false
}
