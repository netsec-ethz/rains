//rainsSiglib provides helperfunctions to sign messages and sections and to verify the validity of signatures on messages and sections
//These helperfunctions are not in rainslib because then we would have a circular dependency as we need rainslib and zoneFileParser to check signatures

package rainsSiglib

import (
	"fmt"
	"regexp"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
)

//CheckSectionSignatures verifies all signatures on the section. Expired signatures are removed.
//Returns true if all signatures are correct.
//
//Process is defined as:
//1) check that there is at least one signature
//2) check that string fields do not contain  <whitespace>:<non whitespace>:<whitespace>
//3) sort section
//4) encode section
//5) sign the encoding and compare the resulting signature data with the signature data received with the section. The encoding of the
//   signature meta data is added in the verifySignature() method
func CheckSectionSignatures(s rainslib.MessageSectionWithSig, pkeys map[rainslib.PublicKeyID][]rainslib.PublicKey, encoder rainslib.SignatureFormatEncoder,
	maxVal rainslib.MaxCacheValidity) bool {
	log.Debug(fmt.Sprintf("Check %T signature", s), "section", s)
	if s == nil {
		log.Warn("section is nil")
		return false
	}
	if pkeys == nil {
		log.Warn("pkeys map is nil")
		return false
	}
	if len(s.Sigs(rainslib.RainsKeySpace)) == 0 {
		log.Debug("Section contain no signatures")
		return true
	}
	if !checkStringFields(s) {
		return false //error already logged
	}
	s.Sort()
	encodedSection := encoder.EncodeSection(s)
	for i, sig := range s.Sigs(rainslib.RainsKeySpace) {
		if keys, ok := pkeys[sig.PublicKeyID]; ok {
			if int64(sig.ValidUntil) < time.Now().Unix() {
				log.Info("signature is expired", "signature", sig)
				s.DeleteSig(i)
				continue
			}
			if key, ok := getPublicKey(keys, sig.GetSignatureMetaData()); ok {
				if !sig.VerifySignature(key.Key, encodedSection) {
					log.Warn("Signature does not match", "encoding", encodedSection, "signature", sig)
					return false
				}
				log.Debug("Signature was valid")
				rainslib.UpdateSectionValidity(s, key.ValidSince, key.ValidUntil, sig.ValidSince, sig.ValidUntil, maxVal)
			} else {
				log.Warn("No time overlapping publicKey in keys for signature", "keys", keys, "signature", sig)
				return false
			}
		} else {
			log.Warn("No publicKey in keymap matching algorithm type", "keymap", pkeys, "algorithmType", sig.Algorithm)
			return false
		}
	}
	return true
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
func CheckMessageSignatures(msg *rainslib.RainsMessage, publicKey rainslib.PublicKey, encoder rainslib.SignatureFormatEncoder) bool {
	log.Debug("Check Message signature")
	if msg == nil {
		log.Warn("msg is nil")
		return false
	}
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
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Debug("signature is expired", "signature", sig)
			msg.Signatures = append(msg.Signatures[:i], msg.Signatures[i+1:]...)
		} else if !sig.VerifySignature(publicKey.Key, encodedSection) {
			return false
		}
	}
	return len(msg.Signatures) > 0
}

//ValidSectionAndSignature returns true if the section is not nil, all the signatures ValidUntil are
//in the future, the string fields do not contain  <whitespace>:<non whitespace>:<whitespace>, and
//the section's content is sorted (by sorting it).
func ValidSectionAndSignature(s rainslib.MessageSectionWithSig) bool {
	log.Debug("Validating section and signature before signing")
	if s == nil {
		log.Warn("section is nil")
		return false
	}
	for _, sig := range s.AllSigs() {
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Warn("signature is expired", "signature", sig)
			return false
		}
	}
	if !checkStringFields(s) {
		return false
	}
	s.Sort()
	return true
}

//SignSectionUnsafe signs a section with the given private Key and adds the resulting bytestring to
//the given signatures. The shard's or zone's content must already be sorted. It does not check the
//validity of the signature or the section. Returns false if the signature was not added to the
//section
func SignSectionUnsafe(s rainslib.MessageSectionWithSig, privateKey interface{}, sig rainslib.Signature, encoder rainslib.SignatureFormatEncoder) bool {
	log.Debug("Start Signing Section")
	err := (&sig).SignData(privateKey, encoder.EncodeSection(s))
	if err != nil {
		return false
	}
	s.AddSig(sig)
	return true
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
func SignSection(s rainslib.MessageSectionWithSig, privateKey interface{}, sig rainslib.Signature,
	encoder rainslib.SignatureFormatEncoder) bool {
	s.AddSig(sig)
	if !ValidSectionAndSignature(s) {
		return false
	}
	return SignSectionUnsafe(s, privateKey, sig, encoder)
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
func SignMessage(msg *rainslib.RainsMessage, privateKey interface{}, sig rainslib.Signature,
	encoder rainslib.SignatureFormatEncoder) bool {
	log.Debug("Sign Message")
	if msg == nil {
		log.Warn("msg is nil")
		return false
	}
	if sig.ValidUntil < time.Now().Unix() {
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

//checkMessageStringFields returns true if the capabilities and all string fields in the contained
//sections of the given message do not contain a zone file type marker, i.e. not a substring
//matching regrex expression '\s:\S+:\s'
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

//checkStringFields returns true if non of the string fields of the given section contain a zone
//file type marker. It panics if the interface s contains a type but the interfaces value is nil
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

func getPublicKey(keys []rainslib.PublicKey, sigMetaData rainslib.SignatureMetaData) (rainslib.PublicKey, bool) {
	for _, key := range keys {
		if key.ValidSince <= sigMetaData.ValidUntil && key.ValidUntil >= sigMetaData.ValidSince {
			return key, true
		}
	}
	return rainslib.PublicKey{}, false
}
