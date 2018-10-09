//siglib provides helperfunctions to sign messages and sections and to verify the validity of
//signatures on messages and section.

package siglib

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

//CheckSectionSignatures verifies all signatures on the section. Expired signatures are removed.
//Returns true if all signatures are correct. The content of a shard or zone must be sorted. If it
//is not, then the signature verification will fail.
//
//Process is defined as:
//1) check that there is at least one signature
//2) check that string fields do not contain  <whitespace>:<non whitespace>:<whitespace>
//4) encode section
//5) sign the encoding and compare the resulting signature data with the signature data received
//   with the section. The encoding of the
//   signature meta data is added in the verifySignature() method
func CheckSectionSignatures(s section.WithSig, pkeys map[keys.PublicKeyID][]keys.PublicKey,
	maxVal util.MaxCacheValidity) bool {
	log.Debug(fmt.Sprintf("Check %T signature", s), "section", s)
	if s == nil {
		log.Warn("section is nil")
		return false
	}
	if pkeys == nil {
		log.Warn("pkeys map is nil")
		return false
	}
	if len(s.Sigs(keys.RainsKeySpace)) == 0 {
		log.Debug("Section contain no signatures")
		return true
	}
	if !CheckStringFields(s) {
		return false //error already logged
	}
	sigs := s.Sigs(keys.RainsKeySpace)
	s.DeleteAllSigs()
	encoding := new(bytes.Buffer)
	if err := s.MarshalCBOR(cbor.NewCBORWriter(encoding)); err != nil {
		log.Warn("Was not able to marshal section.", "error", err)
		return false
	}
	for _, sig := range sigs {
		if keys, ok := pkeys[sig.PublicKeyID]; ok {
			if int64(sig.ValidUntil) < time.Now().Unix() {
				log.Info("signature is expired", "signature", sig)
				continue
			}
			if key, ok := getPublicKey(keys, sig.MetaData()); ok {
				if !sig.VerifySignature(key.Key, encoding.Bytes()) {
					log.Warn("Sig does not match", "encoding", encoding.String(), "signature", sig)
					return false
				}
				log.Debug("Sig was valid")
				s.AddSig(sig)
				util.UpdateSectionValidity(s, key.ValidSince, key.ValidUntil, sig.ValidSince, sig.ValidUntil, maxVal)
			} else {
				log.Warn("No time overlapping publicKey in keys for signature", "keys", keys, "signature", sig)
				return false
			}
		} else {
			log.Warn("No publicKey in keymap matching algorithm type", "keymap", pkeys, "publicKeyID", sig.PublicKeyID)
			return false
		}
	}
	return len(s.AllSigs()) > 0
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
func CheckMessageSignatures(msg *message.Message, publicKey keys.PublicKey) bool {
	log.Debug("Check Message signature")
	if msg == nil {
		log.Warn("msg is nil")
		return false
	}
	if len(msg.Signatures) == 0 {
		log.Debug("Message does not contain signatures")
		return false
	}
	if !checkMessageStringFields(msg) {
		return false
	}
	msg.Sort()
	sigs := msg.Signatures
	msg.Signatures = []signature.Sig{}
	encoding := new(bytes.Buffer)
	if err := msg.MarshalCBOR(cbor.NewCBORWriter(encoding)); err != nil {
		log.Warn("Was not able to marshal message.", "error", err)
		return false
	}
	for _, sig := range sigs {
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Debug("signature is expired", "signature", sig)
		} else if !sig.VerifySignature(publicKey.Key, encoding.Bytes()) {
			return false
		}
	}
	return true
}

//ValidSectionAndSignature returns true if the section is not nil, all the signatures ValidUntil are
//in the future, the string fields do not contain  <whitespace>:<non whitespace>:<whitespace>, and
//the section's content is sorted (by sorting it).
func ValidSectionAndSignature(s section.WithSig) bool {
	log.Debug("Validating section and signature before signing")
	if s == nil {
		log.Warn("section is nil")
		return false
	}
	if !CheckSignatureNotExpired(s) {
		return false
	}
	if !CheckStringFields(s) {
		return false
	}
	s.Sort()
	return true
}

//CheckSignatureNotExpired returns true if s is nil or all the signatures ValidUntil are in the
//future
func CheckSignatureNotExpired(s section.WithSig) bool {
	if s == nil {
		return true
	}
	for _, sig := range s.AllSigs() {
		if int64(sig.ValidUntil) < time.Now().Unix() {
			log.Warn("signature is expired", "signature", sig)
			return false
		}
	}
	return true
}

//SignSectionUnsafe signs a section with the given private Key and adds the resulting bytestring to
//the given signatures. The shard's or zone's content must already be sorted. It does not check the
//validity of the signature or the section. Returns false if the signature was not added to the
//section.
//FIXME: Note that this function only works if one signature is added. Otherwise the cbor
//marshaller also adds the previous signature to encoding which leads to a different signature.
func SignSectionUnsafe(s section.WithSig, privateKey interface{}, sig signature.Sig) bool {
	if len(s.AllSigs()) != 0 {
		log.Error("Section must not contain a signature. FIXME")
		return false
	}
	encoding := new(bytes.Buffer)
	if err := s.MarshalCBOR(cbor.NewCBORWriter(encoding)); err != nil {
		log.Warn("Was not able to marshal section.", "error", err)
		return false
	}
	log.Debug("Marshalling section successful")
	if err := (&sig).SignData(privateKey, encoding.Bytes()); err != nil {
		log.Error(err.Error())
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
func SignSection(s section.WithSig, privateKey interface{}, sig signature.Sig) bool {
	s.AddSig(sig)
	if !ValidSectionAndSignature(s) {
		return false
	}
	s.DeleteSig(0)
	log.Debug("Checks before signing were successful")
	return SignSectionUnsafe(s, privateKey, sig)
}

//SignMessageUnsafe signs a message with the given private Key and adds the resulting bytestring to
//the given signature. The messages content must already be sorted. It does not check the
//validity of the signature or the message. Returns false if the signature was not added to the
//message.
//FIXME: Note that this function only works if one signature is added. Otherwise the cbor
//marshaller also adds the previous signature to encoding which leads to a different signature.
func SignMessageUnsafe(msg *message.Message, privateKey interface{}, sig signature.Sig) bool {
	if len(msg.Signatures) != 0 {
		log.Error("Message must not contain a signature. FIXME")
		return false
	}
	encoding := new(bytes.Buffer)
	if err := msg.MarshalCBOR(cbor.NewCBORWriter(encoding)); err != nil {
		log.Warn("Was not able to marshal message.", "error", err)
		return false
	}
	log.Debug("Marshalling section successful")
	if err := (&sig).SignData(privateKey, encoding.Bytes()); err != nil {
		log.Error(err.Error())
		return false
	}
	msg.Signatures = append(msg.Signatures, sig)
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
func SignMessage(msg *message.Message, privateKey interface{}, sig signature.Sig) bool {
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
	return SignMessageUnsafe(msg, privateKey, sig)
}

//checkMessageStringFields returns true if the capabilities and all string fields in the contained
//sections of the given message do not contain a zone file type marker, i.e. not a substring
//matching regrex expression '\s:\S+:\s'
func checkMessageStringFields(msg *message.Message) bool {
	if msg == nil || !checkCapabilities(msg.Capabilities) {
		return false
	}
	for _, s := range msg.Content {
		if !CheckStringFields(s) {
			return false
		}
	}
	return true
}

//CheckStringFields returns true if non of the string fields of the given section contain a zone
//file type marker. It panics if the interface s contains a type but the interfaces value is nil
func CheckStringFields(s section.Section) bool {
	switch s := s.(type) {
	case *section.Assertion:
		if containsZoneFileType(s.SubjectName) {
			log.Warn("Section contains a string field with forbidden content", "SubjectName", s.SubjectName)
			return false
		}
		if !checkObjectFields(s.Content) {
			return false
		}
		return !(containsZoneFileType(s.Context) || containsZoneFileType(s.SubjectZone))
	case *section.Shard:
		if containsZoneFileType(s.RangeFrom) {
			log.Warn("Section contains a string field with forbidden content", "RangeFrom", s.RangeFrom)
			return false
		}
		if containsZoneFileType(s.RangeTo) {
			log.Warn("Section contains a string field with forbidden content", "RangeTo", s.RangeTo)
			return false
		}
		for _, a := range s.Content {
			if !CheckStringFields(a) {
				return false
			}
		}
		return !(containsZoneFileType(s.Context) || containsZoneFileType(s.SubjectZone))
	case *section.Zone:
		for _, section := range s.Content {
			if !CheckStringFields(section) {
				return false
			}
		}
		return !(containsZoneFileType(s.Context) || containsZoneFileType(s.SubjectZone))
	case *query.Name:
		if containsZoneFileType(s.Context) {
			return false
		}
		if containsZoneFileType(s.Name) {
			log.Warn("Section contains a string field with forbidden content", "QueryName", s.Name)
			return false
		}
	case *section.Notification:
		if containsZoneFileType(s.Data) {
			log.Warn("Section contains a string field with forbidden content", "NotificationData", s.Data)
			return false
		}
	case *section.AddrAssertion:
		if !checkObjectFields(s.Content) {
			return false
		}
		return !containsZoneFileType(s.Context)
	case *query.Address:
		return !containsZoneFileType(s.Context)
	default:
		log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
		return false
	}
	return true
}

func checkObjectFields(objs []object.Object) bool {
	for _, obj := range objs {
		switch obj.Type {
		case object.OTName:
			if nameObj, ok := obj.Value.(object.Name); ok {
				if containsZoneFileType(nameObj.Name) {
					log.Warn("Section contains an object with a string field containing forbidden content", "name", nameObj.Name)
					return false
				}
			}
		case object.OTIP6Addr:
		case object.OTIP4Addr:
		case object.OTRedirection:
			if containsZoneFileType(obj.Value.(string)) {
				log.Warn("Section contains an object with a string field containing forbidden content", "redirection", obj.Value)
				return false
			}
		case object.OTDelegation:
		case object.OTNameset:
			if containsZoneFileType(string(obj.Value.(object.NamesetExpr))) {
				log.Warn("Section contains an object with a string field containing forbidden content", "nameSetExpr", obj.Value)
				return false
			}
		case object.OTCertInfo:
		case object.OTServiceInfo:
			if srvInfo, ok := obj.Value.(object.ServiceInfo); ok {
				if containsZoneFileType(srvInfo.Name) {
					log.Warn("Section contains an object with a string field containing forbidden content", "srvInfoName", srvInfo.Name)
					return false
				}
			}
		case object.OTRegistrar:
			if containsZoneFileType(obj.Value.(string)) {
				log.Warn("Section contains an object with a string field containing forbidden content", "registrar", obj.Value)
				return false
			}
		case object.OTRegistrant:
			if containsZoneFileType(obj.Value.(string)) {
				log.Warn("Section contains an object with a string field containing forbidden content", "registrant", obj.Value)
				return false
			}
		case object.OTInfraKey:
		case object.OTExtraKey:
		case object.OTNextKey:
		default:
			log.Warn("Unsupported obj type", "type", fmt.Sprintf("%T", obj.Type))
			return false
		}
	}
	return true
}

func checkCapabilities(caps []message.Capability) bool {
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

func getPublicKey(pkeys []keys.PublicKey, sigMetaData signature.MetaData) (keys.PublicKey, bool) {
	for _, key := range pkeys {
		if key.ValidSince <= sigMetaData.ValidUntil && key.ValidUntil >= sigMetaData.ValidSince {
			return key, true
		}
	}
	return keys.PublicKey{}, false
}
