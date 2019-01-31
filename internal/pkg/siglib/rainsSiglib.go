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

//CheckSectionSignatures verifies all signatures on s and its content. It assumes that s is sorted.
//Expired signatures are removed. Returns true if all non expired signatures are correct.
func CheckSectionSignatures(s section.WithSig, pkeys map[keys.PublicKeyID][]keys.PublicKey,
	maxVal util.MaxCacheValidity) bool {
	s.DontAddSigInMarshaller()
	if !checkSectionSignatures(s, pkeys, maxVal) {
		return false
	}
	switch s := s.(type) {
	case *section.Shard:
		s.AddCtxAndZoneToContent()
		for _, a := range s.Content {
			if len(a.Sigs(keys.RainsKeySpace)) > 0 && !checkSectionSignatures(a, pkeys, maxVal) {
				return false
			}
		}
		s.RemoveCtxAndZoneFromContent()
	case *section.Zone:
		s.AddCtxAndZoneToContent()
		for _, a := range s.Content {
			if len(a.Sigs(keys.RainsKeySpace)) > 0 && !checkSectionSignatures(a, pkeys, maxVal) {
				return false
			}
		}
		s.RemoveCtxAndZoneFromContent()
	}
	s.AddSigInMarshaller()
	return true
}

//checkSectionSignatures verifies all signatures on the section (but not signatures on the section's
//content). It assumes that the section is sorted. Expired signatures are removed. Returns true if
//all non expired signatures are correct.
func checkSectionSignatures(s section.WithSig, pkeys map[keys.PublicKeyID][]keys.PublicKey,
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
	sigs := s.Sigs(keys.RainsKeySpace)
	if len(sigs) == 0 {
		log.Debug("Section contain no signatures")
		return true
	}
	if !CheckStringFields(s) {
		return false //error already logged
	}
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
					log.Warn("Sig does not match", "section", s, "encoding", encoding.Bytes(), "signature", sig)
					return false
				}
				log.Debug("Sig was valid", "section", s, "encoding", encoding.Bytes(), "signature", sig)
				s.AddSig(sig)
				updateSectionValidity(s, key.ValidSince, key.ValidUntil, sig.ValidSince, sig.ValidUntil, maxVal)
			} else {
				log.Warn("No time overlapping publicKey in keys for signature", "keys", keys, "signature", sig)
				return false
			}
		} else {
			log.Warn("No publicKey in keymap matching algorithm type", "keymap", pkeys, "publicKeyID", sig.PublicKeyID)
			return false
		}
	}
	return len(s.Sigs(keys.RainsKeySpace)) > 0
}

//SignSectionUnsafe signs a section and all contained assertions with the given private Key and
//adds the resulting bytestring to the given signatures. s must be sorted. It does not check the
//validity of s or sig. Returns false if the signature was not added to the section.
func SignSectionUnsafe(s section.WithSig, ks map[keys.PublicKeyID]interface{}) error {
	s.DontAddSigInMarshaller()
	if err := signSectionUnsafe(s, ks); err != nil {
		return err
	}
	switch s := s.(type) {
	case *section.Shard:
		s.AddCtxAndZoneToContent()
		for _, a := range s.Content {
			if len(a.Sigs(keys.RainsKeySpace)) > 0 {
				if err := signSectionUnsafe(a, ks); err != nil {
					return err
				}
			}
		}
		s.RemoveCtxAndZoneFromContent()
	case *section.Zone:
		s.AddCtxAndZoneToContent()
		for _, a := range s.Content {
			if len(a.Sigs(keys.RainsKeySpace)) > 0 {
				if err := signSectionUnsafe(a, ks); err != nil {
					return err
				}
			}
		}
		s.RemoveCtxAndZoneFromContent()
	}
	s.AddSigInMarshaller()
	return nil
}

//signSectionUnsafe signs a section with the given private Key and adds the resulting bytestring to
//the given signatures. It assumes that s is sorted, the sign flag is set to true, and contained
//assertions have a non-empty zone and context values. It does not check the validity of s or sig.
//Returns false if it was not able to sign all signatures
func signSectionUnsafe(s section.WithSig, ks map[keys.PublicKeyID]interface{}) error {
	encoding := new(bytes.Buffer)
	if err := s.MarshalCBOR(cbor.NewCBORWriter(encoding)); err != nil {
		return fmt.Errorf("Was not able to marshal section: %v", err)
	}
	log.Debug("Marshalling section successful")
	sigs := s.Sigs(keys.RainsKeySpace)
	s.DeleteAllSigs()
	for _, sig := range sigs {
		if err := (&sig).SignData(ks[sig.PublicKeyID], encoding.Bytes()); err != nil {
			return err
		}
		s.AddSig(sig)
	}
	return nil
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
	case *section.Pshard:
		if containsZoneFileType(s.RangeFrom) {
			log.Warn("Section contains a string field with forbidden content", "RangeFrom", s.RangeFrom)
			return false
		}
		if containsZoneFileType(s.RangeTo) {
			log.Warn("Section contains a string field with forbidden content", "RangeTo", s.RangeTo)
			return false
		}
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
		case object.OTScionAddr6:
		case object.OTScionAddr4:
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

//updateSectionValidity updates the validity of the section according to the signature validity and the publicKey validity used to verify this signature
func updateSectionValidity(sec section.WithSig, pkeyValidSince, pkeyValidUntil, sigValidSince,
	sigValidUntil int64, maxVal util.MaxCacheValidity) {
	if sec != nil {
		var maxValidity time.Duration
		switch sec.(type) {
		case *section.Assertion:
			maxValidity = maxVal.AssertionValidity
		case *section.Shard:
			maxValidity = maxVal.ShardValidity
		case *section.Pshard:
			maxValidity = maxVal.PshardValidity
		case *section.Zone:
			maxValidity = maxVal.ZoneValidity
		default:
			log.Warn("Not supported section", "type", fmt.Sprintf("%T", sec))
			return
		}
		if pkeyValidSince < sigValidSince {
			if pkeyValidUntil < sigValidUntil {
				sec.UpdateValidity(sigValidSince, pkeyValidUntil, maxValidity)
			} else {
				sec.UpdateValidity(sigValidSince, sigValidUntil, maxValidity)
			}

		} else {
			if pkeyValidUntil < sigValidUntil {
				sec.UpdateValidity(pkeyValidSince, pkeyValidUntil, maxValidity)
			} else {
				sec.UpdateValidity(pkeyValidSince, sigValidUntil, maxValidity)
			}
		}
	}
}
