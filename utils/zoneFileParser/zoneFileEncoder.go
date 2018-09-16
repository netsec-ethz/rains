package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//encodeZone return z in zonefile format. If addZoneAndContext is true, the context and subject zone
//are present also for all contained sections.
func encodeZone(z *rainslib.ZoneSection, addZoneAndContext bool) string {
	zone := fmt.Sprintf("%s %s %s [\n", TypeZone, z.SubjectZone, z.Context)
	for _, section := range z.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			zone += encodeAssertion(section, z.Context, z.SubjectZone, indent4, addZoneAndContext)
		case *rainslib.ShardSection:
			zone += encodeShard(section, z.Context, z.SubjectZone, indent4, addZoneAndContext)
		default:
			log.Warn("Unsupported message section type", "msgSection", section)
		}
	}
	return fmt.Sprintf("%s]\n", zone)
}

//encodeShard returns s in zonefile format. If addZoneAndContext is true, the context and subject
//zone are present for the shard and for all contained assertions.
func encodeShard(s *rainslib.ShardSection, context, subjectZone, indent string, addZoneAndContext bool) string {
	rangeFrom := s.RangeFrom
	rangeTo := s.RangeTo
	if rangeFrom == "" {
		rangeFrom = "<"
	}
	if rangeTo == "" {
		rangeTo = ">"
	}
	var shard string
	if addZoneAndContext {
		shard = fmt.Sprintf("%s %s %s %s %s [\n", TypeShard, subjectZone, context, rangeFrom, rangeTo)
	} else {
		shard = fmt.Sprintf("%s %s %s [\n", TypeShard, rangeFrom, rangeTo)
	}
	for _, assertion := range s.Content {
		shard += encodeAssertion(assertion, context, subjectZone, indent+indent4, addZoneAndContext)
	}
	return fmt.Sprintf("%s%s%s]\n", indent, shard, indent)
}

//encodeAssertion returns a in zonefile format. If addZoneAndContext is true, the context and
//subject zone are also present.
func encodeAssertion(a *rainslib.AssertionSection, context, zone, indent string, addZoneAndContext bool) string {
	var assertion string
	if addZoneAndContext {
		assertion = fmt.Sprintf("%s%s %s %s %s [ ", indent, TypeAssertion, a.SubjectName, zone, context)
	} else {
		assertion = fmt.Sprintf("%s%s %s [ ", indent, TypeAssertion, a.SubjectName)
	}
	if len(a.Content) > 1 {
		return fmt.Sprintf("%s\n%s\n%s]\n", assertion, encodeObjects(a.Content, indent+indent4), indent)
	}
	return fmt.Sprintf("%s%s ]\n", assertion, encodeObjects(a.Content, ""))
}

//encodeObjects returns o in zonefile format.
func encodeObjects(o []rainslib.Object, indent string) string {
	var objects []string
	for _, obj := range o {
		object := indent
		switch obj.Type {
		case rainslib.OTName:
			if nameObj, ok := obj.Value.(rainslib.NameObject); ok {
				object += fmt.Sprintf("%s%s", addIndentToType(TypeName), encodeNameObject(nameObj))
			} else {
				log.Error("Type assertion failed. Expected rainslib.NameObject", "actualType", fmt.Sprintf("%T", obj.Value))
				return ""
			}
		case rainslib.OTIP6Addr:
			object += fmt.Sprintf("%s%s", addIndentToType(TypeIP6), obj.Value)
		case rainslib.OTIP4Addr:
			object += fmt.Sprintf("%s%s", addIndentToType(TypeIP4), obj.Value)
		case rainslib.OTRedirection:
			object += fmt.Sprintf("%s%s", addIndentToType(TypeRedirection), obj.Value)
		case rainslib.OTDelegation:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				object += fmt.Sprintf("%s%s", addIndentToType(TypeDelegation), encodeEd25519PublicKey(pkey))
			} else {
				log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
				return ""
			}
		case rainslib.OTNameset:
			object += fmt.Sprintf("%s%s", addIndentToType(TypeNameSet), obj.Value)
		case rainslib.OTCertInfo:
			if cert, ok := obj.Value.(rainslib.CertificateObject); ok {
				object += fmt.Sprintf("%s%s", addIndentToType(TypeCertificate), encodeCertificate(cert))
			} else {
				log.Warn("Type assertion failed. Expected rainslib.CertificateObject", "actualType", fmt.Sprintf("%T", obj.Value))
				return ""
			}
		case rainslib.OTServiceInfo:
			if srvInfo, ok := obj.Value.(rainslib.ServiceInfo); ok {
				object += fmt.Sprintf("%s%s %d %d", addIndentToType(TypeServiceInfo), srvInfo.Name, srvInfo.Port, srvInfo.Priority)
			} else {
				log.Warn("Type assertion failed. Expected rainslib.ServiceInfo", "actualType", fmt.Sprintf("%T", obj.Value))
				return ""
			}
		case rainslib.OTRegistrar:
			object += fmt.Sprintf("%s%s", addIndentToType(TypeRegistrar), obj.Value)
		case rainslib.OTRegistrant:
			object += fmt.Sprintf("%s%s", addIndentToType(TypeRegistrant), obj.Value)
		case rainslib.OTInfraKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				object += fmt.Sprintf("%s%s", addIndentToType(TypeInfraKey), encodeEd25519PublicKey(pkey))
			} else {
				log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
				return ""
			}
		case rainslib.OTExtraKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				object += fmt.Sprintf("%s%s %s", addIndentToType(TypeExternalKey), encodeKeySpace(pkey.KeySpace), encodeEd25519PublicKey(pkey))
			} else {
				log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
				return ""
			}
		case rainslib.OTNextKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				object += fmt.Sprintf("%s%s %d %d", addIndentToType(TypeNextKey), encodeEd25519PublicKey(pkey), pkey.ValidSince, pkey.ValidUntil)
			} else {
				log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
				return ""
			}
		default:
			log.Warn("Unsupported obj type", "type", fmt.Sprintf("%T", obj.Type))
			return ""
		}
		objects = append(objects, object)
	}
	return strings.Join(objects, "\n")
}

//addIndentToType returns the object type ot with appropriate indent such that the object value start at the same
//indent.
func addIndentToType(ot string) string {
	result := "          "
	return ot + result[len(ot):]
}

//encodeNameObject returns no represented as a string in zone file format.
func encodeNameObject(no rainslib.NameObject) string {
	nameObject := []string{}
	for _, oType := range no.Types {
		switch oType {
		case rainslib.OTName:
			nameObject = append(nameObject, TypeName)
		case rainslib.OTIP6Addr:
			nameObject = append(nameObject, TypeIP6)
		case rainslib.OTIP4Addr:
			nameObject = append(nameObject, TypeIP4)
		case rainslib.OTRedirection:
			nameObject = append(nameObject, TypeRedirection)
		case rainslib.OTDelegation:
			nameObject = append(nameObject, TypeDelegation)
		case rainslib.OTNameset:
			nameObject = append(nameObject, TypeNameSet)
		case rainslib.OTCertInfo:
			nameObject = append(nameObject, TypeCertificate)
		case rainslib.OTServiceInfo:
			nameObject = append(nameObject, TypeServiceInfo)
		case rainslib.OTRegistrar:
			nameObject = append(nameObject, TypeRegistrar)
		case rainslib.OTRegistrant:
			nameObject = append(nameObject, TypeRegistrant)
		case rainslib.OTInfraKey:
			nameObject = append(nameObject, TypeInfraKey)
		case rainslib.OTExtraKey:
			nameObject = append(nameObject, TypeExternalKey)
		case rainslib.OTNextKey:
			nameObject = append(nameObject, TypeNextKey)
		default:
			log.Warn("Unsupported object type in nameObject", "actualType", oType, "nameObject", no)
		}
	}
	return fmt.Sprintf("%s [ %s ]", no.Name, strings.Join(nameObject, " "))
}

//encodeEd25519PublicKey returns pkey represented as a string in zone file format.
func encodeEd25519PublicKey(pkey rainslib.PublicKey) string {
	if key, ok := pkey.Key.(ed25519.PublicKey); ok {
		return fmt.Sprintf("%s %d %s", TypeEd25519, pkey.KeyPhase, hex.EncodeToString(key))
	}
	log.Warn("Type assertion failed. Expected rainslib.Ed25519PublicKey", "actualType", fmt.Sprintf("%T", pkey.Key))
	return ""
}

//encodeKeySpace returns keySpace represented as a string in zone file format.
func encodeKeySpace(keySpace rainslib.KeySpaceID) string {
	switch keySpace {
	case rainslib.RainsKeySpace:
		return TypeKSRains
	default:
		log.Warn("Unsupported key space type", "actualType", keySpace)
	}
	return ""
}

//encodeCertificate returns cert represented as a string in zone file format.
func encodeCertificate(cert rainslib.CertificateObject) string {
	var pt, cu, ca string
	switch cert.Type {
	case rainslib.PTUnspecified:
		pt = TypeUnspecified
	case rainslib.PTTLS:
		pt = TypePTTLS
	default:
		log.Warn("Unsupported protocol type", "protocolType", cert.Type)
		return ""
	}
	switch cert.Usage {
	case rainslib.CUTrustAnchor:
		cu = TypeCUTrustAnchor
	case rainslib.CUEndEntity:
		cu = TypeCUEndEntity
	default:
		log.Warn("Unsupported certificate usage", "certUsage", cert.Usage)
		return ""
	}
	switch cert.HashAlgo {
	case rainslib.NoHashAlgo:
		ca = TypeNoHash
	case rainslib.Sha256:
		ca = TypeSha256
	case rainslib.Sha384:
		ca = TypeSha384
	case rainslib.Sha512:
		ca = TypeSha512
	default:
		log.Warn("Unsupported certificate hash algorithm type", "hashAlgoType", cert.HashAlgo)
		return ""
	}
	return fmt.Sprintf("%s %s %s %s", pt, cu, ca, hex.EncodeToString(cert.Data))
}
