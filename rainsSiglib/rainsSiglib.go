package rainsSiglib

import (
	"encoding/hex"
	"fmt"
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
	log.Debug("Check Section signature")
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
			continue
		} else if !sig.VerifySignature(pkey.Key, encodedSection) {
			log.Warn("", "publicKey", hex.EncodeToString(pkey.Key.(ed25519.PublicKey)), "encoded Section", encodedSection, "signature", sig)
			return false
		}
		rainslib.UpdateSectionValidity(s, pkey.ValidSince, pkey.ValidUntil, sig.ValidSince, sig.ValidUntil, maxVal)
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
		} else if !sig.VerifySignature(publicKey.Key, encodedSection) {
			log.Warn("", "publicKey", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)), "encoded Section", encodedSection, "signature", sig)
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
	err := (&sig).SignData(privateKey, encoder.EncodeSection(s))
	if err != nil {
		return false
	}
	s.AddSig(sig)
	return true
}

//SignMessage signs a message with the given private Key and adds the resulting bytestring to the given signature.
//Signatures with validUntil in the past are not signed and added
//Returns false if the signature was not added to the message
//
//Process is defined as:
//1) check that the signature's ValidUntil is in the future
//2) check that string fields do not contain  <whitespace>:<non whitespace>:<whitespace>
//3) sort message
//4) encode message
//5) sign the encoding and add it to the signature which will then be added to the message. The encoding of the
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
	err := (&sig).SignData(privateKey, encoder.EncodeMessage(msg))
	if err != nil {
		return false
	}
	msg.Signatures = append(msg.Signatures, sig)
	return true
}

//checkMessageStringFields returns true if the capabilities and all string fields in the contained sections of the given message
//do not contain a zone file type marker, i.e. not a substring matching regrex expression '\s:\S+:\s'
func checkMessageStringFields(msg *rainslib.RainsMessage) bool {
	if msg == nil || !checkCapabilites(msg.Capabilities) {
		return false
	}
	for _, s := range msg.Content {
		if !checkStringFields(s) {
			return false
		}
	}
	return true
}

//checkStringFields returns true if non of the string fields of the given section contain a zone file type marker,
func checkStringFields(s rainslib.MessageSection) bool {
	switch s := s.(type) {
	case *rainslib.AssertionSection:
		if containsZoneFileType(s.SubjectName) {
			log.Warn("Section contains a string field with forbidden content", "SubjectName", s.SubjectName)
			return false
		}
		if !checkObjectFields(s.Content) {
			return false
		}
		return !(containsZoneFileType(s.Context) || containsZoneFileType(s.SubjectZone))
	case *rainslib.ShardSection:
		if containsZoneFileType(s.RangeFrom) {
			log.Warn("Section contains a string field with forbidden content", "RangeFrom", s.RangeFrom)
			return false
		}
		if containsZoneFileType(s.RangeTo) {
			log.Warn("Section contains a string field with forbidden content", "RangeTo", s.RangeTo)
			return false
		}
		for _, a := range s.Content {
			if !checkStringFields(a) {
				return false
			}
		}
		return !(containsZoneFileType(s.Context) || containsZoneFileType(s.SubjectZone))
	case *rainslib.ZoneSection:
		for _, section := range s.Content {
			if !checkStringFields(section) {
				return false
			}
		}
		return !(containsZoneFileType(s.Context) || containsZoneFileType(s.SubjectZone))
	case *rainslib.QuerySection:
		if containsZoneFileType(s.Context) {
			return false
		}
		if containsZoneFileType(s.Name) {
			log.Warn("Section contains a string field with forbidden content", "QueryName", s.Name)
			return false
		}
	case *rainslib.NotificationSection:
		if containsZoneFileType(s.Data) {
			log.Warn("Section contains a string field with forbidden content", "NotificationData", s.Data)
			return false
		}
	case *rainslib.AddressAssertionSection:
		if !checkObjectFields(s.Content) {
			return false
		}
		return !containsZoneFileType(s.Context)
	case *rainslib.AddressZoneSection:
		for _, a := range s.Content {
			if !checkStringFields(a) {
				return false
			}
		}
		return !containsZoneFileType(s.Context)
	case *rainslib.AddressQuerySection:
		return !containsZoneFileType(s.Context)
	default:
		log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
		return false
	}
	return true
}

func checkObjectFields(objs []rainslib.Object) bool {
	for _, obj := range objs {
		switch obj.Type {
		case rainslib.OTName:
			if nameObj, ok := obj.Value.(rainslib.NameObject); ok {
				if containsZoneFileType(nameObj.Name) {
					log.Warn("Section contains an object with a string field containing forbidden content", "name", nameObj.Name)
					return false
				}
			}
		case rainslib.OTIP6Addr:
		case rainslib.OTIP4Addr:
		case rainslib.OTRedirection:
			if containsZoneFileType(obj.Value.(string)) {
				log.Warn("Section contains an object with a string field containing forbidden content", "redirection", obj.Value)
				return false
			}
		case rainslib.OTDelegation:
		case rainslib.OTNameset:
			if containsZoneFileType(string(obj.Value.(rainslib.NamesetExpression))) {
				log.Warn("Section contains an object with a string field containing forbidden content", "nameSetExpr", obj.Value)
				return false
			}
		case rainslib.OTCertInfo:
		case rainslib.OTServiceInfo:
			if srvInfo, ok := obj.Value.(rainslib.ServiceInfo); ok {
				if containsZoneFileType(srvInfo.Name) {
					log.Warn("Section contains an object with a string field containing forbidden content", "srvInfoName", srvInfo.Name)
					return false
				}
			}
		case rainslib.OTRegistrar:
			if containsZoneFileType(obj.Value.(string)) {
				log.Warn("Section contains an object with a string field containing forbidden content", "registrar", obj.Value)
				return false
			}
		case rainslib.OTRegistrant:
			if containsZoneFileType(obj.Value.(string)) {
				log.Warn("Section contains an object with a string field containing forbidden content", "registrant", obj.Value)
				return false
			}
		case rainslib.OTInfraKey:
		case rainslib.OTExtraKey:
		case rainslib.OTNextKey:
		default:
			log.Warn("Unsupported obj type", "type", fmt.Sprintf("%T", obj.Type))
			return false
		}
	}
	return true
}

func checkCapabilites(caps []rainslib.Capability) bool {
	for _, c := range caps {
		if containsZoneFileType(string(c)) {
			return false
		}
	}
	return true
}

//containsZoneFileType returns true if input contains a zone file type definition expression
func containsZoneFileType(input string) bool {
	re := regexp.MustCompile("\\s:\\S+:\\s|^:\\S+:\\s|\\s:\\S+:$|^:\\S+:$")
	if re.FindString(input) != "" {
		log.Warn("The input contains forbidden content", "input", input)
		return true
	}
	return false
}
