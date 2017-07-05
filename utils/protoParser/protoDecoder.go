package protoParser

import (
	"errors"
	"fmt"
	"net"
	"rains/proto"
	"rains/rainslib"
	"strconv"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func decodeAssertion(a proto.AssertionSection) (*rainslib.AssertionSection, error) {
	assertion := rainslib.AssertionSection{}
	var err error

	assertion.Context, err = a.Context()
	if err != nil {
		log.Warn("Was not able to decode context", "error", err)
		return nil, err
	}

	assertion.SubjectZone, err = a.SubjectZone()
	if err != nil {
		log.Warn("Was not able to decode SubjectZone", "error", err)
		return nil, err
	}

	assertion.SubjectName, err = a.SubjectName()
	if err != nil {
		log.Warn("Was not able to decode SubjectName", "error", err)
		return nil, err
	}

	sigList, err := a.Signatures()
	if err != nil {
		log.Warn("Could not decode signature list", "error", err)
		return nil, err
	}
	assertion.Signatures, err = decodeSignatures(sigList)
	if err != nil {
		return nil, err
	}

	content, err := a.Content()
	if err != nil {
		log.Warn("Could not decode object list", "error", err)
		return nil, err
	}
	assertion.Content, err = decodeObjects(content)
	if err != nil {
		return nil, err
	}

	return &assertion, nil
}

func decodeShard(s proto.ShardSection) (*rainslib.ShardSection, error) {
	shard := rainslib.ShardSection{}
	var err error

	shard.Context, err = s.Context()
	if err != nil {
		log.Warn("Was not able to decode context", "error", err)
		return nil, err
	}

	shard.SubjectZone, err = s.SubjectZone()
	if err != nil {
		log.Warn("Was not able to decode SubjectZone", "error", err)
		return nil, err
	}

	shard.RangeFrom, err = s.RangeFrom()
	if err != nil {
		log.Warn("Was not able to decode rangeFrom", "error", err)
		return nil, err
	}

	shard.RangeTo, err = s.RangeTo()
	if err != nil {
		log.Warn("Was not able to decode rangeTo", "error", err)
		return nil, err
	}

	sigList, err := s.Signatures()
	if err != nil {
		log.Warn("Could not decode signature list", "error", err)
		return nil, err
	}
	shard.Signatures, err = decodeSignatures(sigList)
	if err != nil {
		return nil, err
	}

	assertionList, err := s.Content()
	if err != nil {
		log.Warn("Could not decode assertion list", "error", err)
		return nil, err
	}
	for i := 0; i < assertionList.Len(); i++ {
		assertion, err := decodeAssertion(assertionList.At(i))
		if err != nil {
			return nil, err
		}
		shard.Content = append(shard.Content, assertion)
	}

	return &shard, nil
}

func decodeZone(z proto.ZoneSection) (*rainslib.ZoneSection, error) {
	zone := rainslib.ZoneSection{}
	var err error

	zone.Context, err = z.Context()
	if err != nil {
		log.Warn("Was not able to decode context", "error", err)
		return nil, err
	}

	zone.SubjectZone, err = z.SubjectZone()
	if err != nil {
		log.Warn("Was not able to decode SubjectZone", "error", err)
		return nil, err
	}

	sigList, err := z.Signatures()
	if err != nil {
		log.Warn("Could not decode signature list", "error", err)
		return nil, err
	}
	zone.Signatures, err = decodeSignatures(sigList)
	if err != nil {
		return nil, err
	}

	sectionList, err := z.Content()
	if err != nil {
		log.Warn("Could not decode section list", "error", err)
		return nil, err
	}
	for i := 0; i < sectionList.Len(); i++ {
		section := sectionList.At(i)
		switch section.Which() {
		case proto.MessageSection_Which_assertion:
			a, err := section.Assertion()
			if err != nil {
				log.Warn("Could not extract assertion", "error", err)
				return nil, err
			}
			assertion, err := decodeAssertion(a)
			if err != nil {
				return nil, err
			}
			zone.Content = append(zone.Content, assertion)
		case proto.MessageSection_Which_shard:
			s, err := section.Shard()
			if err != nil {
				log.Warn("Could not extract shard", "error", err)
				return nil, err
			}
			shard, err := decodeShard(s)
			if err != nil {
				return nil, err
			}
			zone.Content = append(zone.Content, shard)
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", section))
			return nil, errors.New("Unsupported section type")
		}
	}

	return &zone, nil
}

func decodeQuery(q proto.QuerySection) (*rainslib.QuerySection, error) {
	query := rainslib.QuerySection{}
	var err error

	query.Expires = q.Expires()
	query.Type = rainslib.ObjectType(q.Type())

	query.Context, err = q.Context()
	if err != nil {
		log.Warn("Was not able to decode context", "error", err)
		return nil, err
	}

	query.Name, err = q.Name()
	if err != nil {
		log.Warn("Was not able to decode name", "error", err)
		return nil, err
	}

	optList, err := q.Options()
	if err != nil {
		log.Warn("Was not able to decode query options", "error", err)
		return nil, err
	}
	for i := 0; i < optList.Len(); i++ {
		query.Options = append(query.Options, rainslib.QueryOption(optList.At(i)))
	}

	return &query, nil
}

func decodeNotification(n proto.NotificationSection) (*rainslib.NotificationSection, error) {
	notification := rainslib.NotificationSection{}

	notification.Type = rainslib.NotificationType(n.Type())

	tok, err := n.Token()
	if err != nil {
		log.Warn("Could not decode token", "error", err)
		return nil, err
	}
	length := 16
	if len(tok) < 16 {
		length = len(tok)
	}
	copy(notification.Token[:], tok[:length])

	notification.Data, err = n.Data()
	if err != nil {
		log.Warn("Was not able to decode data", "error", err)
		return nil, err
	}
	return &notification, nil
}

func decodeAddressAssertion(a proto.AddressAssertionSection) (*rainslib.AddressAssertionSection, error) {
	assertion := rainslib.AddressAssertionSection{}

	ipCIDR, err := a.SubjectAddr()
	if err != nil {
		log.Warn("Was not able to decode subjectAddr", "error", err)
		return nil, err
	}
	_, assertion.SubjectAddr, err = net.ParseCIDR(ipCIDR)
	if err != nil {
		log.Warn("Could not parse IP in CIDR notation to *net.IPNet", "address", ipCIDR, "error", err)
		return nil, err
	}

	assertion.Context, err = a.Context()
	if err != nil {
		log.Warn("Was not able to decode context", "error", err)
		return nil, err
	}

	sigList, err := a.Signatures()
	if err != nil {
		log.Warn("Could not decode signature list", "error", err)
		return nil, err
	}
	assertion.Signatures, err = decodeSignatures(sigList)
	if err != nil {
		return nil, err
	}

	content, err := a.Content()
	if err != nil {
		log.Warn("Could not decode object list", "error", err)
		return nil, err
	}
	assertion.Content, err = decodeObjects(content)
	if err != nil {
		return nil, err
	}

	return &assertion, nil
}

func decodeAddressZone(z proto.AddressZoneSection) (*rainslib.AddressZoneSection, error) {
	zone := rainslib.AddressZoneSection{}

	ipCIDR, err := z.SubjectAddr()
	if err != nil {
		log.Warn("Was not able to decode subjectAddr", "error", err)
		return nil, err
	}
	_, zone.SubjectAddr, err = net.ParseCIDR(ipCIDR)
	if err != nil {
		log.Warn("Could not parse IP in CIDR notation to *net.IPNet", "address", ipCIDR, "error", err)
		return nil, err
	}

	zone.Context, err = z.Context()
	if err != nil {
		log.Warn("Was not able to decode context", "error", err)
		return nil, err
	}

	sigList, err := z.Signatures()
	if err != nil {
		log.Warn("Could not decode signature list", "error", err)
		return nil, err
	}
	zone.Signatures, err = decodeSignatures(sigList)
	if err != nil {
		return nil, err
	}

	assertionList, err := z.Content()
	if err != nil {
		log.Warn("Could not decode assertion list", "error", err)
		return nil, err
	}
	for i := 0; i < assertionList.Len(); i++ {
		assertion, err := decodeAddressAssertion(assertionList.At(i))
		if err != nil {
			return nil, err
		}
		zone.Content = append(zone.Content, assertion)
	}

	return &zone, nil
}

func decodeAddressQuery(q proto.AddressQuerySection) (*rainslib.AddressQuerySection, error) {
	query := rainslib.AddressQuerySection{}

	query.Expires = q.Expires()
	query.Type = rainslib.ObjectType(q.Types())

	ipCIDR, err := q.SubjectAddr()
	if err != nil {
		log.Warn("Was not able to decode subjectAddr", "error", err)
		return nil, err
	}
	_, query.SubjectAddr, err = net.ParseCIDR(ipCIDR)
	if err != nil {
		log.Warn("Could not parse IP in CIDR notation to *net.IPNet", "address", ipCIDR, "error", err)
		return nil, err
	}

	query.Context, err = q.Context()
	if err != nil {
		log.Warn("Was not able to decode context", "error", err)
		return nil, err
	}

	optList, err := q.Options()
	if err != nil {
		log.Warn("Was not able to decode query options", "error", err)
		return nil, err
	}
	for i := 0; i < optList.Len(); i++ {
		query.Options = append(query.Options, rainslib.QueryOption(optList.At(i)))
	}

	return &query, nil
}

func decodeObjects(objList proto.Obj_List) ([]rainslib.Object, error) {
	objects := []rainslib.Object{}

	for i := 0; i < objList.Len(); i++ {
		object := rainslib.Object{}
		var err error
		obj := objList.At(i)
		object.Type = rainslib.ObjectType(obj.Type())
		switch obj.Value().Which() {
		case proto.Obj_value_Which_name:
			object.Value, err = decodeObjectName(obj.Value())
			if err != nil {
				return nil, err
			}
		case proto.Obj_value_Which_ip6:
			object.Value, err = obj.Value().Ip6()
			if err != nil {
				log.Warn("Was not able to decode ip6 object value", "error", err)
				return nil, err
			}
		case proto.Obj_value_Which_ip4:
			object.Value, err = obj.Value().Ip4()
			if err != nil {
				log.Warn("Was not able to decode ip4 object value", "error", err)
				return nil, err
			}
		case proto.Obj_value_Which_redir:
			object.Value, err = obj.Value().Redir()
			if err != nil {
				log.Warn("Was not able to decode redirection object value", "error", err)
				return nil, err
			}
		case proto.Obj_value_Which_deleg:
			pkey, err := obj.Value().Deleg()
			if err != nil {
				log.Warn("Was not able to decode delegation object value", "error", err)
				return nil, err
			}
			object.Value, err = decodePublicKey(pkey)
			if err != nil {
				return nil, err
			}
		case proto.Obj_value_Which_nameset:
			nameSet, err := obj.Value().Nameset()
			if err != nil {
				log.Warn("Was not able to decode nameset object value", "error", err)
				return nil, err
			}
			object.Value = rainslib.NamesetExpression(nameSet)
		case proto.Obj_value_Which_cert:
			object.Value, err = decodeCert(obj.Value())
			if err != nil {
				return nil, err
			}
		case proto.Obj_value_Which_service:
			object.Value, err = decodeServiceInfo(obj.Value())
			if err != nil {
				return nil, err
			}
		case proto.Obj_value_Which_regr:
			object.Value, err = obj.Value().Regr()
			if err != nil {
				log.Warn("Was not able to decode registrar object value", "error", err)
				return nil, err
			}
		case proto.Obj_value_Which_regt:
			object.Value, err = obj.Value().Regt()
			if err != nil {
				log.Warn("Was not able to decode registrant object value", "error", err)
				return nil, err
			}
		case proto.Obj_value_Which_infra:
			pkey, err := obj.Value().Infra()
			if err != nil {
				log.Warn("Was not able to decode infrastructure object value", "error", err)
				return nil, err
			}
			object.Value, err = decodePublicKey(pkey)
			if err != nil {
				return nil, err
			}
		case proto.Obj_value_Which_extra:
			pkey, err := obj.Value().Extra()
			if err != nil {
				log.Warn("Was not able to decode extraKey object value", "error", err)
				return nil, err
			}
			object.Value, err = decodePublicKey(pkey)
			if err != nil {
				return nil, err
			}
		case proto.Obj_value_Which_next:
			pkey, err := obj.Value().Next()
			if err != nil {
				log.Warn("Was not able to decode nextKey object value", "error", err)
				return nil, err
			}
			object.Value, err = decodePublicKey(pkey)
			if err != nil {
				return nil, err
			}
		default:
			log.Warn("Unsupported object type", "type", fmt.Sprintf("%T", obj.Value()))
			return nil, errors.New("Unsupported object type")
		}
		objects = append(objects, object)
	}

	return objects, nil
}

func decodeObjectName(value proto.Obj_value) (rainslib.NameObject, error) {
	nameList, err := value.Name()
	if err != nil {
		log.Warn("Was not able to decode name object value", "error", err)
		return rainslib.NameObject{}, err
	}
	nameObject := rainslib.NameObject{}
	nameObject.Name, err = nameList.At(0)
	if err != nil {
		log.Warn("Was not able to decode name object value", "error", err)
		return rainslib.NameObject{}, err
	}
	for j := 1; j < nameList.Len(); j++ {
		t, err := nameList.At(j)
		if err != nil {
			log.Warn("Was not able to decode name object value", "error", err)
			return rainslib.NameObject{}, err
		}
		objType, err := strconv.Atoi(t)
		if err != nil {
			log.Warn("Was not able to convert string to int (objectType)", "error", err)
			return rainslib.NameObject{}, err
		}
		nameObject.Types = append(nameObject.Types, rainslib.ObjectType(objType))
	}
	return nameObject, nil
}

func decodeCert(value proto.Obj_value) (rainslib.CertificateObject, error) {
	c, err := value.Cert()
	if err != nil {
		log.Warn("Was not able to decode cert object value", "error", err)
		return rainslib.CertificateObject{}, err
	}
	cert := rainslib.CertificateObject{
		Type:     rainslib.ProtocolType(c.Type()),
		HashAlgo: rainslib.HashAlgorithmType(c.HashAlgo()),
		Usage:    rainslib.CertificateUsage(c.Usage()),
	}
	cert.Data, err = c.Data()
	if err != nil {
		log.Warn("Was not able to decode cert data value", "error", err)
		return rainslib.CertificateObject{}, err
	}
	return cert, nil
}

func decodeServiceInfo(value proto.Obj_value) (rainslib.ServiceInfo, error) {
	si, err := value.Service()
	if err != nil {
		log.Warn("Was not able to decode service info object value", "error", err)
		return rainslib.ServiceInfo{}, err
	}
	serviceInfo := rainslib.ServiceInfo{
		Port:     uint16(si.Port()),
		Priority: uint(si.Priority()),
	}

	serviceInfo.Name, err = si.Name()
	if err != nil {
		log.Warn("Was not able to decode service info name", "error", err)
		return rainslib.ServiceInfo{}, err
	}
	return serviceInfo, nil
}

func decodeSignatures(sigList proto.Signature_List) ([]rainslib.Signature, error) {
	signatures := []rainslib.Signature{}
	for i := 0; i < sigList.Len(); i++ {
		sig := sigList.At(i)
		signature := rainslib.Signature{
			KeySpace:   rainslib.KeySpaceID(sig.KeySpace()),
			Algorithm:  rainslib.SignatureAlgorithmType(sig.Algorithm()),
			ValidSince: sig.ValidSince(),
			ValidUntil: sig.ValidUntil()}
		data, err := sig.Data()
		if err != nil {
			log.Warn("Was not able to decode signature data", "error", err)
			return nil, err
		}
		signature.Data = data
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

func decodeContent(contentList proto.MessageSection_List) ([]rainslib.MessageSection, error) {
	sections := []rainslib.MessageSection{}
	for i := 0; i < contentList.Len(); i++ {
		content := contentList.At(i)
		switch content.Which() {
		case proto.MessageSection_Which_assertion:
			a, err := content.Assertion()
			if err != nil {
				log.Warn("Was not able to extract Assertion", "error", err)
				return nil, err
			}
			assertion, err := decodeAssertion(a)
			if err != nil {
				log.Warn("Was not able to decode Assertion", "error", err)
				return nil, err
			}
			sections = append(sections, assertion)
		case proto.MessageSection_Which_shard:
			s, err := content.Shard()
			if err != nil {
				log.Warn("Was not able to extract Shard", "error", err)
				return nil, err
			}
			shard, err := decodeShard(s)
			if err != nil {
				log.Warn("Was not able to decode Shard", "error", err)
				return nil, err
			}
			sections = append(sections, shard)
		case proto.MessageSection_Which_zone:
			z, err := content.Zone()
			if err != nil {
				log.Warn("Was not able to extract Zone", "error", err)
				return nil, err
			}
			zone, err := decodeZone(z)
			if err != nil {
				log.Warn("Was not able to decode Zone", "error", err)
				return nil, err
			}
			sections = append(sections, zone)
		case proto.MessageSection_Which_query:
			q, err := content.Query()
			if err != nil {
				log.Warn("Was not able to extract Query", "error", err)
				return nil, err
			}
			query, err := decodeQuery(q)
			if err != nil {
				log.Warn("Was not able to decode Query", "error", err)
				return nil, err
			}
			sections = append(sections, query)
		case proto.MessageSection_Which_notification:
			n, err := content.Notification()
			if err != nil {
				log.Warn("Was not able to extract Notification", "error", err)
				return nil, err
			}
			notification, err := decodeNotification(n)
			if err != nil {
				log.Warn("Was not able to decode Notification", "error", err)
				return nil, err
			}
			sections = append(sections, notification)
		case proto.MessageSection_Which_addressAssertion:
			a, err := content.AddressAssertion()
			if err != nil {
				log.Warn("Was not able to extract AddressAssertion", "error", err)
				return nil, err
			}
			assertion, err := decodeAddressAssertion(a)
			if err != nil {
				log.Warn("Was not able to decode AddressAssertion", "error", err)
				return nil, err
			}
			sections = append(sections, assertion)
		case proto.MessageSection_Which_addressZone:
			z, err := content.AddressZone()
			if err != nil {
				log.Warn("Was not able to extract AddressZone", "error", err)
				return nil, err
			}
			zone, err := decodeAddressZone(z)
			if err != nil {
				log.Warn("Was not able to decode AddressZone", "error", err)
				return nil, err
			}
			sections = append(sections, zone)
		case proto.MessageSection_Which_addressQuery:
			q, err := content.AddressQuery()
			if err != nil {
				log.Warn("Was not able to extract AddressQuery", "error", err)
				return nil, err
			}
			query, err := decodeAddressQuery(q)
			if err != nil {
				log.Warn("Was not able to decode AddressQuery", "error", err)
				return nil, err
			}
			sections = append(sections, query)
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", content))
			return nil, errors.New("Unsupported section type")
		}
	}
	return sections, nil
}

func decodePublicKey(pkey proto.PublicKey) (rainslib.PublicKey, error) {
	publicKey := rainslib.PublicKey{
		KeySpace:   rainslib.KeySpaceID(pkey.KeySpace()),
		Type:       rainslib.SignatureAlgorithmType(pkey.Type()),
		ValidSince: pkey.ValidSince(),
		ValidUntil: pkey.ValidUntil(),
	}
	switch publicKey.Type {
	case rainslib.Ed25519:
		pubKey, err := pkey.Key()
		publicKey.Key = ed25519.PublicKey(pubKey)
		if err != nil {
			log.Warn("Was not able to decode key data", "error", err)
			return rainslib.PublicKey{}, err
		}
	case rainslib.Ed448:
		log.Warn("Not yet supported")
	case rainslib.Ecdsa256:
		log.Warn("Not yet supported")
	case rainslib.Ecdsa384:
		log.Warn("Not yet supported")
	default:
		log.Warn("Unsupported public key type", "type", fmt.Sprintf("%T", publicKey.Type))
		return rainslib.PublicKey{}, errors.New("Unsupported public key type")
	}
	return publicKey, nil
}
