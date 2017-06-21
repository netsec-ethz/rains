package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"rains/rainslib"
	"strings"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//encodeZone return z as a string. If toSign is true, the return value is in signable format
//i.e. that the context and subject zone are present also for all contained sections
//Otherwise the output is a string representation of the zone file generated from z.
func encodeZone(z *rainslib.ZoneSection, toSign bool) string {
	zone := fmt.Sprintf(":Z: %s %s [\n", z.SubjectZone, z.Context)
	for _, section := range z.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			context, subjectZone := getContextAndZone(z.Context, z.SubjectZone, section, toSign)
			zone += fmt.Sprintf("%s%s\n", indent4, encodeAssertion(section, context, subjectZone, indent4))
		case *rainslib.ShardSection:
			context, subjectZone := getContextAndZone(z.Context, z.SubjectZone, section, toSign)
			zone += fmt.Sprintf("%s%s\n", indent4, encodeShard(section, context, subjectZone, toSign))
		default:
			log.Warn("Unsupported message section type", "msgSection", section)
		}
	}
	return fmt.Sprintf("%s]", zone)
}

//encodeShard returns s as a string. If toSign is true, the return value is in signable format
//i.e. that the context and subject zone are present also for all contained assertions
//Otherwise the output is a string representation of s in zone file format.
func encodeShard(s *rainslib.ShardSection, context, subjectZone string, toSign bool) string {
	rangeFrom := s.RangeFrom
	rangeTo := s.RangeTo
	if rangeFrom == "" {
		rangeFrom = "<"
	}
	if rangeTo == "" {
		rangeTo = ">"
	}
	shard := fmt.Sprintf(":S: %s %s %s %s [\n", subjectZone, context, rangeFrom, rangeTo)
	for _, assertion := range s.Content {
		ctx, zone := getContextAndZone(context, subjectZone, assertion, toSign)
		shard += fmt.Sprintf("%s%s\n", indent8, encodeAssertion(assertion, ctx, zone, indent8))
	}
	return fmt.Sprintf("%s%s]", shard, indent4)
}

//encodeAssertion returns a as a string. If toSign is true, the return value is in signable format
//i.e. that the context and subject zone are present also for all contained assertions
//Otherwise the output is a string representation of s in zone file format.
func encodeAssertion(a *rainslib.AssertionSection, context, zone, indent string) string {
	assertion := fmt.Sprintf(":A: %s %s %s [ ", a.SubjectName, zone, context)
	if len(a.Content) > 1 {
		return fmt.Sprintf("%s\n%s\n%s]", assertion, encodeObjects(a.Content, indent12), indent)
	}
	return fmt.Sprintf("%s%s ]", assertion, encodeObjects(a.Content, ""))
}

//encodeObjects returns o represented as a string in zone file format where indent determines the indent added before the each object
func encodeObjects(o []rainslib.Object, indent string) string {
	objects := ""
	for _, obj := range o {
		objects += indent
		switch obj.Type {
		case rainslib.OTName:
			if nameObj, ok := obj.Value.(rainslib.NameObject); ok {
				objects += fmt.Sprintf("%s     %s\n", typeName, encodeNameObject(nameObj))
				continue
			}
			log.Warn("Type assertion failed. Expected rainslib.NameObject", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTIP6Addr:
			objects += fmt.Sprintf("%s      %s\n", typeIP6, obj.Value)
		case rainslib.OTIP4Addr:
			objects += fmt.Sprintf("%s      %s\n", typeIP4, obj.Value)
		case rainslib.OTRedirection:
			objects += fmt.Sprintf("%s    %s\n", typeRedirection, obj.Value)
		case rainslib.OTDelegation:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				objects += fmt.Sprintf("%s    %s\n", typeDelegation, encodePublicKey(pkey))
				continue
			}
			log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTNameset:
			objects += fmt.Sprintf("%s  %s\n", typeNameSet, obj.Value)
		case rainslib.OTCertInfo:
			if cert, ok := obj.Value.(rainslib.CertificateObject); ok {
				objects += fmt.Sprintf("%s     %s\n", typeCertificate, encodeCertificate(cert))
				continue
			}
			log.Warn("Type assertion failed. Expected rainslib.CertificateObject", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTServiceInfo:
			if srvInfo, ok := obj.Value.(rainslib.ServiceInfo); ok {
				objects += fmt.Sprintf("%s      %s %d %d\n", typeServiceInfo, srvInfo.Name, srvInfo.Port, srvInfo.Priority)
				continue
			}
			log.Warn("Type assertion failed. Expected rainslib.ServiceInfo", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTRegistrar:
			objects += fmt.Sprintf("%s     %s\n", typeRegistrar, obj.Value)
		case rainslib.OTRegistrant:
			objects += fmt.Sprintf("%s     %s\n", typeRegistrant, obj.Value)
		case rainslib.OTInfraKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				objects += fmt.Sprintf("%s    %s\n", typeInfraKey, encodePublicKey(pkey))
				continue
			}
			log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTExtraKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				objects += fmt.Sprintf("%s    %s %s\n", typeExternalKey, encodeKeySpace(pkey.KeySpace), encodePublicKey(pkey))
				continue
			}
			log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTNextKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				objects += fmt.Sprintf("%s     %s %d %d\n", typeNextKey, encodePublicKey(pkey), pkey.ValidSince, pkey.ValidUntil)
				continue
			}
			log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
		default:
			log.Warn("Unsupported obj type", "type", fmt.Sprintf("%T", obj.Type))
		}
	}
	if len(o) > 0 {
		objects = objects[:len(objects)-1] //remove the last new line
	}
	return objects
}

//encodeNameObject returns no represented as a string in zone file format.
func encodeNameObject(no rainslib.NameObject) string {
	nameObject := []string{}
	for _, oType := range no.Types {
		switch oType {
		case rainslib.OTName:
			nameObject = append(nameObject, otName)
		case rainslib.OTIP6Addr:
			nameObject = append(nameObject, otIP6)
		case rainslib.OTIP4Addr:
			nameObject = append(nameObject, otIP4)
		case rainslib.OTRedirection:
			nameObject = append(nameObject, otRedirection)
		case rainslib.OTDelegation:
			nameObject = append(nameObject, otDelegation)
		case rainslib.OTNameset:
			nameObject = append(nameObject, otNameSet)
		case rainslib.OTCertInfo:
			nameObject = append(nameObject, otCertificate)
		case rainslib.OTServiceInfo:
			nameObject = append(nameObject, otServiceInfo)
		case rainslib.OTRegistrar:
			nameObject = append(nameObject, otRegistrar)
		case rainslib.OTRegistrant:
			nameObject = append(nameObject, otRegistrant)
		case rainslib.OTInfraKey:
			nameObject = append(nameObject, otInfraKey)
		case rainslib.OTExtraKey:
			nameObject = append(nameObject, otExternalKey)
		default:

		}
	}
	return fmt.Sprintf("%s [ %s ]", no.Name, strings.Join(nameObject, " "))
}

//encodePublicKey returns pkey represented as a string in zone file format.
func encodePublicKey(pkey rainslib.PublicKey) string {
	switch pkey.Type {
	case rainslib.Ed25519:
		if key, ok := pkey.Key.(ed25519.PublicKey); ok {
			return fmt.Sprintf("%s %s", keyAlgoed25519, hex.EncodeToString(key))
		}
		log.Warn("Type assertion failed. ExpsOTServiceInfoected rainslib.Ed25519PublicKey", "actualType", fmt.Sprintf("%T", pkey.Key))
	case rainslib.Ed448:
		if key, ok := pkey.Key.(rainslib.Ed448PublicKey); ok {
			return fmt.Sprintf("%s %s", keyAlgoed448, hex.EncodeToString(key[:]))
		}
		log.Warn("Type assertion failed. Expected rainslib.Ed448PublicKey", "type", fmt.Sprintf("%T", pkey.Key))
	case rainslib.Ecdsa256:
		log.Warn("Not yet implemented")
		return ""
	case rainslib.Ecdsa384:
		log.Warn("Not yet implemented")
		return ""
	default:
		log.Warn("Unsupported signature algorithm type", "actualType", pkey.Type)

	}
	return ""
}

//encodeKeySpace returns keySpace represented as a string in zone file format.
func encodeKeySpace(keySpace rainslib.KeySpaceID) string {
	switch keySpace {
	case rainslib.RainsKeySpace:
		return ksRains
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
		pt = unspecified
	case rainslib.PTTLS:
		pt = ptTLS
	default:
		log.Warn("Unsupported protocol type", "protocolType", cert.Type)
		return ""
	}
	switch cert.Usage {
	case rainslib.CUTrustAnchor:
		cu = cuTrustAnchor
	case rainslib.CUEndEntity:
		cu = cuEndEntity
	default:
		log.Warn("Unsupported certificate usage", "certUsage", cert.Usage)
		return ""
	}
	switch cert.HashAlgo {
	case rainslib.NoHashAlgo:
		ca = haNone
	case rainslib.Sha256:
		ca = haSha256
	case rainslib.Sha384:
		ca = haSha384
	case rainslib.Sha512:
		ca = haSha512
	default:
		log.Warn("Unsupported certificate hash algorithm type", "hashAlgoType", cert.HashAlgo)
		return ""
	}
	return fmt.Sprintf("%s %s %s %s", pt, cu, ca, hex.EncodeToString(cert.Data))
}

//getContextAndZone return the context and subjectZone to be used in contained assertions or shards.
//if toSign is true it returns the context and subjectZone from the outer section.
func getContextAndZone(outerContext, outerZone string, containedSection rainslib.MessageSectionWithSigForward, toSign bool) (string, string) {
	if toSign {
		return outerContext, outerZone
	}
	return containedSection.GetContext(), containedSection.GetSubjectZone()
}
