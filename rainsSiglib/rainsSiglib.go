package rainsSiglib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
	"rains/rainslib"
	"regexp"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//CheckSectionSignatures verifies all signatures on the section. Expired signatures are removed.
//Returns true if at least one signature is valid and all signatures are correct.
//
//Process is defined as:
//1) check that there is at least one signature
//2) check that string fields do not contain  <whitespace>:<non whitespace>:<whitespace>
//3) sort section
//4) encode section
//5) sign the encoding and compare the resulting signature data with the signature data received with the section. The encoding of the
//   signature meta data is added in the verifySignature() method
func CheckSectionSignatures(s rainslib.MessageSectionWithSig, pkeys map[rainslib.KeyAlgorithmType]rainslib.PublicKey, encoder rainslib.SignatureFormatEncoder,
	maxVal rainslib.MaxCacheValidity) bool {
	if len(s.Sigs()) == 0 {
		log.Debug("Section contain no signatures")
		return false
	}
	if !checkStringFields(s) {
		return false
	}
	s.Sort()
	encodedSection := encoder.EncodeSection(s)
	for i, sig := range s.Sigs() {
		pkey := pkeys[rainslib.KeyAlgorithmType(sig.Algorithm)]
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Debug("signature is expired", "signature", sig)
			s.DeleteSig(i)
		} else if !verifySignature(sig, pkey.Key, encodedSection) {
			return false
		} else {
			rainslib.UpdateSectionValidity(s, pkey.ValidSince, pkey.ValidUntil, sig.ValidSince, sig.ValidUntil, maxVal)
		}
	}
	return len(s.Sigs()) > 0
}

//CheckMessageSignatures verifies all signatures on the message. Signatures that are not valid now are removed.
//Returns true if at least one signature is valid and all signatures are correct.
//
//Process is defined as:
//1) check that there is at least one signature
//2) check that string fields do not contain  <whitespace>:<non whitespace>:<whitespace>
//3) sort message
//4) encode message
//5) sign the encoding and compare the resulting signature data with the signature data received with the message. The encoding of the
//   signature meta data is added in the verifySignature() method
func CheckMessageSignatures(msg *rainslib.RainsMessage, publicKey rainslib.PublicKey, encoder rainslib.SignatureFormatEncoder, maxVal rainslib.MaxCacheValidity) bool {
	if len(msg.Signatures) == 0 {
		log.Debug("Message contain no signatures")
		return false
	}
	if !checkMessageStringFields(msg) {
		return false
	}
	msg.Sort()
	encodedSection := encoder.EncodeMessage(msg)
	for i, sig := range msg.Signatures {
		if int64(sig.ValidUntil) < time.Now().Unix() || int64(sig.ValidSince) > time.Now().Unix() {
			log.Debug("current time is not in this signature's validity period", "signature", sig)
			msg.Signatures = append(msg.Signatures[:i], msg.Signatures[i+1:]...)
		} else if !verifySignature(sig, publicKey.Key, encodedSection) {
			return false
		}
	}
	return len(msg.Signatures) > 0
}

//SignSection signs a section with the given private Key and adds the resulting bytestring to the given signature.
//Signatures with validUntil in the past are not signed and added
//Returns false if the signature was not added to the section
//
//Process is defined as:
//1) check that the signature's ValidUntil is in the future
//2) check that string fields do not contain  <whitespace>:<non whitespace>:<whitespace>
//3) sort section
//4) encode section
//5) sign the encoding and add it to the signature which will then be added to the section. The encoding of the
//   signature meta data is added in the verifySignature() method
func SignSection(s rainslib.MessageSectionWithSig, privateKey interface{}, sig rainslib.Signature, encoder rainslib.SignatureFormatEncoder) bool {
	if int64(sig.ValidUntil) < time.Now().Unix() {
		log.Warn("signature is expired", "signature", sig)
		return false
	}
	if !checkStringFields(s) {
		return false
	}
	s.Sort()
	signData(&sig, privateKey, encoder.EncodeSection(s))
	s.AddSig(sig)
	return true
}

//SignMessage signs a message with the given private Key and adds the resulting bytestring to the given signature.
//Signatures with validUntil in the past are not signed and added
//Returns false if the signature was not added to the section
//
//Process is defined as:
//1) check that the signature's ValidUntil is in the future
//2) check that string fields do not contain  <whitespace>:<non whitespace>:<whitespace>
//3) sort section
//4) encode section
//5) sign the encoding and add it to the signature which will then be added to the section. The encoding of the
//   signature meta data is added in the verifySignature() method
func SignMessage(msg *rainslib.RainsMessage, privateKey interface{}, sig rainslib.Signature, encoder rainslib.SignatureFormatEncoder) bool {
	if int64(sig.ValidUntil) < time.Now().Unix() {
		log.Warn("signature is expired", "signature", sig)
		return false
	}
	if !checkMessageStringFields(msg) {
		return false
	}
	msg.Sort()
	signData(&sig, privateKey, encoder.EncodeMessage(msg))
	msg.Signatures = append(msg.Signatures, sig)
	return true
}

//checkMessageStringFields returns true if the capabilities and all string fields in the contained sections of the given message
//do not contain a zone file type marker, i.e. not a substring matching regrex expression '\s:\S+:\s'
func checkMessageStringFields(msg *rainslib.RainsMessage) bool {
	re := regexp.MustCompile("\\s:\\S+:\\s")
	if !checkCapabilites(msg.Capabilities, re) {
		return false
	}
	for _, s := range msg.Content {
		if !checkStringFields(s) {
			return false
		}
	}
	return true
}

//checkStringFields returns true if all string fields of the given section do not contain a zone file type marker,
//i.e. not a substring matching regrex expression '\s:\S+:\s'
func checkStringFields(s rainslib.MessageSection) bool {
	re := regexp.MustCompile("\\s:\\S+:\\s")
	switch s := s.(type) {
	case *rainslib.AssertionSection:
		if re.FindString(s.SubjectName) != "" {
			log.Warn("Section contains a string field with forbidden content", "SubjectName", s.SubjectName)
			return false
		}
		if !checkObjectFields(s.Content, re) {
			return false
		}
		return checkContextAndZoneFields(s, re)
	case *rainslib.ShardSection:
		if re.FindString(s.RangeFrom) != "" {
			log.Warn("Section contains a string field with forbidden content", "RangeFrom", s.RangeFrom)
			return false
		}
		if re.FindString(s.RangeTo) != "" {
			log.Warn("Section contains a string field with forbidden content", "RangeTo", s.RangeTo)
			return false
		}
		for _, a := range s.Content {
			if !checkStringFields(a) {
				return false
			}
		}
		return checkContextAndZoneFields(s, re)
	case *rainslib.ZoneSection:
		for _, section := range s.Content {
			if !checkStringFields(section) {
				return false
			}
		}
		return checkContextAndZoneFields(s, re)
	case *rainslib.QuerySection:
		if !checkContextField(s.Context, re) {
			return false
		}
		if re.FindString(s.Name) != "" {
			log.Warn("Section contains a string field with forbidden content", "QueryName", s.Name)
			return false
		}
	case *rainslib.NotificationSection:
		if re.FindString(s.Data) != "" {
			log.Warn("Section contains a string field with forbidden content", "NotificationData", s.Data)
			return false
		}
	case *rainslib.AddressAssertionSection:
		if !checkObjectFields(s.Content, re) {
			return false
		}
		return checkContextField(s.Context, re)
	case *rainslib.AddressZoneSection:
		for _, a := range s.Content {
			if !checkStringFields(a) {
				return false
			}
		}
		return checkContextField(s.Context, re)
	case *rainslib.AddressQuerySection:
		return checkContextField(s.Context, re)
	default:
		log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
		return false
	}
	return true
}

func checkContextField(context string, re *regexp.Regexp) bool {
	if re.FindString(context) != "" {
		log.Warn("Section contains a string field with forbidden content", "context", context)
		return false
	}
	return true
}

func checkContextAndZoneFields(s rainslib.MessageSectionWithSig, re *regexp.Regexp) bool {
	checkContextField(s.GetContext(), re)
	if re.FindString(s.GetSubjectZone()) != "" {
		log.Warn("Section contains a string field with forbidden content", "subjectZone", s.GetSubjectZone())
		return false
	}
	return true

}

func checkObjectFields(objs []rainslib.Object, re *regexp.Regexp) bool {
	for _, obj := range objs {
		switch obj.Type {
		case rainslib.OTName:
			if nameObj, ok := obj.Value.(rainslib.NameObject); ok {
				if re.FindString(nameObj.Name) != "" {
					log.Warn("Section contains an object with a string field containing forbidden content", "name", nameObj.Name)
					return false
				}
			}
		case rainslib.OTIP6Addr:
		case rainslib.OTIP4Addr:
		case rainslib.OTRedirection:
			if re.FindString(obj.Value.(string)) != "" {
				log.Warn("Section contains an object with a string field containing forbidden content", "redirection", obj.Value)
				return false
			}
		case rainslib.OTDelegation:
		case rainslib.OTNameset:
			if re.FindString(string(obj.Value.(rainslib.NamesetExpression))) != "" {
				log.Warn("Section contains an object with a string field containing forbidden content", "nameSetExpr", obj.Value)
				return false
			}
		case rainslib.OTCertInfo:
		case rainslib.OTServiceInfo:
			if srvInfo, ok := obj.Value.(rainslib.ServiceInfo); ok {
				if re.FindString(srvInfo.Name) != "" {
					log.Warn("Section contains an object with a string field containing forbidden content", "srvInfoName", srvInfo.Name)
					return false
				}
			}
		case rainslib.OTRegistrar:
			if re.FindString(obj.Value.(string)) != "" {
				log.Warn("Section contains an object with a string field containing forbidden content", "registrar", obj.Value)
				return false
			}
		case rainslib.OTRegistrant:
			if re.FindString(obj.Value.(string)) != "" {
				log.Warn("Section contains an object with a string field containing forbidden content", "registrant", obj.Value)
				return false
			}
		case rainslib.OTInfraKey:
		case rainslib.OTExtraKey:
		case rainslib.OTNextKey:
		default:
			log.Warn("Unsupported obj type", "type", fmt.Sprintf("%T", obj.Type))
		}
	}
	return true
}

func checkCapabilites(caps []rainslib.Capability, re *regexp.Regexp) bool {
	for i, c := range caps {
		if re.FindString(string(c)) != "" {
			log.Warn("The %dth message capability contains forbidden content", "capability", i, c)
			return false
		}
	}
	return true
}

//verifySignature adds signature meta data to the encoding. It then signs it and compares the resulting signature with the given signature.
//Returns true if the signatures are identical
func verifySignature(sig rainslib.Signature, publicKey interface{}, encoding string) bool {
	encoding += fmt.Sprintf("%d %d %d %d", sig.KeySpace, sig.Algorithm, sig.ValidSince, sig.ValidUntil)
	data := []byte(encoding)
	if sig.Data == nil {
		log.Warn("sig does not contain signature data", "sig", sig)
		return false
	}
	switch sig.Algorithm {
	case rainslib.Ed25519:
		if pkey, ok := publicKey.(rainslib.Ed25519PublicKey); ok {
			return ed25519.Verify(ed25519.PublicKey(pkey[:]), data, sig.Data.([]byte))
		}
		log.Warn("Could not cast key to ed25519.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	case rainslib.Ed448:
		log.Warn("Ed448 not yet Supported!")
	case rainslib.Ecdsa256:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := sig.Data.([]*big.Int); ok && len(sig) == 2 {
				hash := sha256.Sum256(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not cast signature ", "signature", sig.Data)
			return false
		}
		log.Warn("Could not cast key to ecdsa.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	case rainslib.Ecdsa384:
		if pkey, ok := publicKey.(*ecdsa.PublicKey); ok {
			if sig, ok := sig.Data.([]*big.Int); ok && len(sig) == 2 {
				hash := sha512.Sum384(data)
				return ecdsa.Verify(pkey, hash[:], sig[0], sig[1])
			}
			log.Warn("Could not cast signature ", "signature", sig.Data)
			return false
		}
		log.Warn("Could not cast key to ecdsa.PublicKey", "publicKeyType", fmt.Sprintf("%T", publicKey))
	default:
		log.Warn("Signature algorithm type not supported", "type", sig.Algorithm)
	}
	return false
}

//signData adds signature meta data to the encoding. It then signs the encoding with the given private key and adds generated signature to sig
func signData(sig *rainslib.Signature, privateKey interface{}, encoding string) {
	encoding += fmt.Sprintf("%d %d %d %d", sig.KeySpace, sig.Algorithm, sig.ValidSince, sig.ValidUntil)
	data := []byte(encoding)
	switch sig.Algorithm {
	case rainslib.Ed25519:
		if pkey, ok := privateKey.(ed25519.PrivateKey); ok {
			sig.Data = ed25519.Sign(pkey, data)
			return
		}
		log.Warn("Could not cast key to ed25519.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
	case rainslib.Ed448:
		log.Warn("Ed448 not yet Supported!")
	case rainslib.Ecdsa256:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha256.Sum256(data)
			sig.Data = signEcdsa(pkey, data, hash[:])
			return
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
	case rainslib.Ecdsa384:
		if pkey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			hash := sha512.Sum384(data)
			sig.Data = signEcdsa(pkey, data, hash[:])
			return
		}
		log.Warn("Could not cast key to ecdsa.PrivateKey", "privateKeyType", fmt.Sprintf("%T", privateKey))
	default:
		log.Warn("Signature algorithm type not supported", "type", sig.Algorithm)
	}
}

func signEcdsa(privateKey *ecdsa.PrivateKey, data, hash []byte) interface{} {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		log.Warn("Could not sign data with Ecdsa256", "error", err)
	}
	return []*big.Int{r, s}
}
