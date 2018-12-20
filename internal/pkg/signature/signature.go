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

// UnmarshalArray takes in a CBOR decoded aray and populates Sig.
func (sig *Sig) UnmarshalArray(in []interface{}) error {
	if len(in) < 6 {
		return fmt.Errorf("expected at least 5 items in input array but got %d", len(in))
	}
	sig.PublicKeyID.Algorithm = algorithmTypes.Signature(in[0].(int))
	sig.PublicKeyID.KeySpace = keys.KeySpaceID(in[1].(int))
	sig.PublicKeyID.KeyPhase = int(in[2].(int))
	sig.ValidSince = int64(in[3].(int))
	sig.ValidUntil = int64(in[4].(int))
	sig.Data = in[5]
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

func (sig MetaData) String() string {
	return fmt.Sprintf("%s %d %d",
		sig.PublicKeyID, sig.ValidSince, sig.ValidUntil)
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

//SignData adds signature meta data to encoding. It then signs the encoding with privateKey and updates sig.Data field with the generated signature
//In case of an error an error is returned indicating the cause, otherwise nil is returned
func (sig *Sig) SignData(privateKey interface{}, encoding []byte) error {
	if privateKey == nil {
		log.Warn("PrivateKey is nil")
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
		log.Warn("Could not assert type ed25519.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
		return errors.New("could not assert type ed25519.PrivateKey")
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
