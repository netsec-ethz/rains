package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"rains/rainslib"
	"strings"

	log "github.com/inconshreveable/log15"
)

func encodeZone(z *rainslib.ZoneSection, toSign bool) string {
	zone := fmt.Sprintf(":Z: %s %s [\n", z.Context, z.SubjectZone)
	for _, section := range z.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			context, subjectZone := getContextAndZone(z.Context, z.SubjectZone, section, toSign)
			zone += fmt.Sprintf("    %s\n", encodeAssertion(section, context, subjectZone, indent4))
		case *rainslib.ShardSection:
			context, subjectZone := getContextAndZone(z.Context, z.SubjectZone, section, toSign)
			zone += fmt.Sprintf("    %s\n", encodeShard(section, context, subjectZone, toSign))
		default:
			log.Warn("Unsupported message section type", "msgSection", section)
		}
	}
	return fmt.Sprintf("%s]", zone)
}

func encodeShard(s *rainslib.ShardSection, context, zone string, toSign bool) string {
	shard := fmt.Sprintf(":S: %s %s %s %s [\n", context, zone, s.RangeFrom, s.RangeTo)
	for _, assertion := range s.Content {
		ctx, subjectZone := getContextAndZone(context, zone, assertion, toSign)
		shard += fmt.Sprintf("        %s\n", encodeAssertion(assertion, ctx, subjectZone, indent8))
	}
	return fmt.Sprintf("%s    ]", shard)
}

func encodeAssertion(a *rainslib.AssertionSection, context, zone, indent string) string {
	assertion := fmt.Sprintf(":A: %s %s %s [ ", context, zone, a.SubjectName)
	if len(a.Content) > 1 {
		return fmt.Sprintf("%s\n%s\n%s]", assertion, encodeObjects(a.Content, indent12), indent)
	}
	return fmt.Sprintf("%s %s ]", assertion, encodeObjects(a.Content, ""))
}

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
		default:
			log.Warn("Unsupported obj type", "type", fmt.Sprintf("%T", obj.Type))
		}
	}
	objects = objects[:len(objects)-1] //remove the last new line
	return objects
}

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

func encodePublicKey(pkey rainslib.PublicKey) string {
	switch pkey.Type {
	case rainslib.Ed25519:
		if key, ok := pkey.Key.(rainslib.Ed25519PublicKey); ok {
			return fmt.Sprintf("%s %s", keyAlgoed25519, hex.EncodeToString(key[:]))
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

func encodeKeySpace(keySpace rainslib.KeySpaceID) string {
	switch keySpace {
	case rainslib.RainsKeySpace:
		return ksRains
	default:
		log.Warn("Unsupported key space type", "actualType", keySpace)
	}
	return ""
}

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

func getContextAndZone(outerContext, outerZone string, containedSection rainslib.MessageSectionWithSigForward, toSign bool) (string, string) {
	context := containedSection.GetContext()
	subjectZone := containedSection.GetSubjectZone()
	if toSign && (context == "" || subjectZone == "") {
		context = outerContext
		subjectZone = outerZone
	}
	return context, subjectZone
}
