package protoParser

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/netsec-ethz/rains/proto"
	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
	capnp "zombiezen.com/go/capnproto2"

	"golang.org/x/crypto/ed25519"
)

func encodeAssertion(a *rainslib.AssertionSection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	assertion, err := msgSection.NewAssertion()
	if err != nil {
		return proto.MessageSection{}, err
	}

	assertion.SetContext(a.Context)
	assertion.SetSubjectZone(a.SubjectZone)
	assertion.SetSubjectName(a.SubjectName)
	sigList, err := assertion.NewSignatures(int32(len(a.Signatures)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	encodeSignatures(a.Signatures, &sigList, seg)

	contentList, err := assertion.NewContent(int32(len(a.Content)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	encodeObjects(a.Content, &contentList, seg)

	return msgSection, nil
}

func encodeShard(s *rainslib.ShardSection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	shard, err := msgSection.NewShard()
	if err != nil {
		return proto.MessageSection{}, err
	}

	shard.SetContext(s.Context)
	shard.SetSubjectZone(s.SubjectZone)
	shard.SetRangeFrom(s.RangeFrom)
	shard.SetRangeTo(s.RangeTo)

	sigList, err := shard.NewSignatures(int32(len(s.Signatures)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	err = encodeSignatures(s.Signatures, &sigList, seg)
	if err != nil {
		return proto.MessageSection{}, err
	}

	contentList, err := shard.NewContent(int32(len(s.Content)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, assertion := range s.Content {
		ms, err := encodeAssertion(assertion, seg)
		if err != nil {
			return proto.MessageSection{}, err
		}
		a, err := ms.Assertion()
		if err != nil {
			return proto.MessageSection{}, err
		}
		contentList.Set(i, a)
	}
	return msgSection, nil
}

func encodeZone(z *rainslib.ZoneSection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	zone, err := msgSection.NewZone()
	if err != nil {
		return proto.MessageSection{}, err
	}

	zone.SetContext(z.Context)
	zone.SetSubjectZone(z.SubjectZone)

	sigList, err := zone.NewSignatures(int32(len(z.Signatures)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	err = encodeSignatures(z.Signatures, &sigList, seg)
	if err != nil {
		return proto.MessageSection{}, err
	}

	contentList, err := zone.NewContent(int32(len(z.Content)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, section := range z.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			ms, err := encodeAssertion(section, seg)
			if err != nil {
				return proto.MessageSection{}, err
			}
			contentList.Set(i, ms)
		case *rainslib.ShardSection:
			ms, err := encodeShard(section, seg)
			if err != nil {
				return proto.MessageSection{}, err
			}
			contentList.Set(i, ms)
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", section))
			return proto.MessageSection{}, errors.New("Unsupported section type")
		}
	}
	return msgSection, nil
}

func encodeQuery(q *rainslib.QuerySection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	query, err := msgSection.NewQuery()
	if err != nil {
		return proto.MessageSection{}, err
	}

	query.SetName(q.Name)
	query.SetContext(q.Context)
	query.SetExpires(q.Expires)

	qtList, err := capnp.NewInt32List(seg, int32(len(q.Types)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, t := range q.Types {
		qtList.Set(i, int32(t))
	}
	query.SetTypes(qtList)

	qoList, err := capnp.NewInt32List(seg, int32(len(q.Options)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, opt := range q.Options {
		qoList.Set(i, int32(opt))
	}
	query.SetOptions(qoList)
	return msgSection, nil
}

func encodeNotification(n *rainslib.NotificationSection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	notification, err := msgSection.NewNotification()
	if err != nil {
		return proto.MessageSection{}, err
	}

	tok := [16]byte(n.Token)
	notification.SetToken(tok[:])
	notification.SetType(int32(n.Type))
	notification.SetData(n.Data)

	return msgSection, nil
}

func encodeAddressAssertion(a *rainslib.AddressAssertionSection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	assertion, err := msgSection.NewAddressAssertion()
	if err != nil {
		return proto.MessageSection{}, err
	}

	assertion.SetContext(a.Context)

	sigList, err := assertion.NewSignatures(int32(len(a.Signatures)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	err = encodeSignatures(a.Signatures, &sigList, seg)
	if err != nil {
		return proto.MessageSection{}, err
	}

	contentList, err := assertion.NewContent(int32(len(a.Content)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	encodeObjects(a.Content, &contentList, seg)

	err = assertion.SetSubjectAddr(a.SubjectAddr.String())
	if err != nil {
		return proto.MessageSection{}, err
	}

	return msgSection, nil
}

func encodeAddressZone(z *rainslib.AddressZoneSection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	zone, err := msgSection.NewAddressZone()
	if err != nil {
		return proto.MessageSection{}, err
	}

	zone.SetContext(z.Context)

	sigList, err := zone.NewSignatures(int32(len(z.Signatures)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	err = encodeSignatures(z.Signatures, &sigList, seg)
	if err != nil {
		return proto.MessageSection{}, err
	}

	err = zone.SetSubjectAddr(z.SubjectAddr.String())
	if err != nil {
		return proto.MessageSection{}, err
	}

	contentList, err := zone.NewContent(int32(len(z.Content)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, assertion := range z.Content {
		ms, err := encodeAddressAssertion(assertion, seg)
		if err != nil {
			return proto.MessageSection{}, err
		}
		a, err := ms.AddressAssertion()
		if err != nil {
			return proto.MessageSection{}, err
		}
		contentList.Set(i, a)
	}

	return msgSection, nil
}

func encodeAddressQuery(q *rainslib.AddressQuerySection, seg *capnp.Segment) (proto.MessageSection, error) {
	msgSection, err := proto.NewMessageSection(seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	query, err := msgSection.NewAddressQuery()
	if err != nil {
		return proto.MessageSection{}, err
	}

	query.SetContext(q.Context)
	query.SetExpires(q.Expires)

	qtList, err := capnp.NewInt32List(seg, int32(len(q.Types)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, t := range q.Types {
		qtList.Set(i, int32(t))
	}
	query.SetTypes(qtList)

	qoList, err := capnp.NewInt32List(seg, int32(len(q.Options)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, opt := range q.Options {
		qoList.Set(i, int32(opt))
	}
	query.SetOptions(qoList)

	err = query.SetSubjectAddr(q.SubjectAddr.String())
	if err != nil {
		return proto.MessageSection{}, err
	}
	return msgSection, nil
}

func encodeSignatures(signatures []rainslib.Signature, list *proto.Signature_List, seg *capnp.Segment) error {
	for i, signature := range signatures {
		sig, err := proto.NewSignature(seg)
		if err != nil {
			return err
		}

		sig.SetKeySpace(int32(signature.KeySpace))
		sig.SetAlgorithm(int32(signature.Algorithm))
		sig.SetValidSince(signature.ValidSince)
		sig.SetValidUntil(signature.ValidUntil)

		switch data := signature.Data.(type) {
		case []byte:
			sig.SetData(data)
		default:
			log.Warn("Unsupported signature data type", "type", fmt.Sprintf("%T", signature.Algorithm))
			return errors.New("Unsupported signature data type")
		}

		list.Set(i, sig)
	}
	return nil
}

func encodeObjects(objects []rainslib.Object, list *proto.Obj_List, seg *capnp.Segment) error {
	for i, object := range objects {
		obj, err := proto.NewObj(seg)
		if err != nil {
			return err
		}
		obj.SetType(int32(object.Type))
		switch object.Type {
		case rainslib.OTName:
			if nameObject, ok := object.Value.(rainslib.NameObject); ok {
				nameList, err := obj.Value().NewName(int32(len(nameObject.Types) + 1))
				if err != nil {
					return err
				}
				nameList.Set(0, nameObject.Name)
				for j, t := range nameObject.Types {
					nameList.Set(j+1, strconv.Itoa(int(t)))
				}
			} else {
				log.Warn("Type assertion failed. Expected ObjectName", "object", object.Value)
				return errors.New("Type assertion failed")
			}
		case rainslib.OTIP6Addr:
			obj.Value().SetIp6(object.Value.(string))
		case rainslib.OTIP4Addr:
			obj.Value().SetIp4(object.Value.(string))
		case rainslib.OTRedirection:
			obj.Value().SetRedir(object.Value.(string))
		case rainslib.OTDelegation:
			pubKey, err := obj.Value().NewDeleg()
			if err != nil {
				return err
			}
			err = encodePublicKey(object.Value.(rainslib.PublicKey), pubKey)
			if err != nil {
				return err
			}
		case rainslib.OTNameset:
			obj.Value().SetNameset(string(object.Value.(rainslib.NamesetExpression)))
		case rainslib.OTCertInfo:
			if cert, ok := object.Value.(rainslib.CertificateObject); ok {
				c, err := obj.Value().NewCert()
				if err != nil {
					return err
				}
				c.SetData(cert.Data)
				c.SetType(int32(cert.Type))
				c.SetHashAlgo(int32(cert.HashAlgo))
				c.SetUsage(int32(cert.Usage))
			} else {
				log.Warn("Type assertion failed. Expected CertificateObject", "object", object.Value)
				return errors.New("Type assertion failed")
			}
		case rainslib.OTServiceInfo:
			if servInfo, ok := object.Value.(rainslib.ServiceInfo); ok {
				si, err := obj.Value().NewService()
				if err != nil {
					return err
				}
				si.SetName(servInfo.Name)
				si.SetPort(servInfo.Port)
				si.SetPriority(uint32(servInfo.Priority))
			} else {
				log.Warn("Type assertion failed. Expected ServiceInfo", "object", object.Value)
				return errors.New("Type assertion failed")
			}
		case rainslib.OTRegistrar:
			obj.Value().SetRegr(object.Value.(string))
		case rainslib.OTRegistrant:
			obj.Value().SetRegt(object.Value.(string))
		case rainslib.OTInfraKey:
			pubKey, err := obj.Value().NewInfra()
			if err != nil {
				return err
			}
			err = encodePublicKey(object.Value.(rainslib.PublicKey), pubKey)
			if err != nil {
				return err
			}
		case rainslib.OTExtraKey:
			pubKey, err := obj.Value().NewExtra()
			if err != nil {
				return err
			}
			err = encodePublicKey(object.Value.(rainslib.PublicKey), pubKey)
			if err != nil {
				return err
			}
		case rainslib.OTNextKey:
			pubKey, err := obj.Value().NewNext()
			if err != nil {
				return err
			}
			err = encodePublicKey(object.Value.(rainslib.PublicKey), pubKey)
			if err != nil {
				return err
			}
		default:
			log.Warn("Unsupported object type", "type", fmt.Sprintf("%T", object.Type))
			return errors.New("Unsupported object type")
		}
		list.Set(i, obj)
	}
	return nil
}

func encodePublicKey(publicKey rainslib.PublicKey, pubKey proto.PublicKey) error {
	pubKey.SetValidSince(publicKey.ValidSince)
	pubKey.SetValidUntil(publicKey.ValidUntil)
	pubKey.SetKeySpace(int32(publicKey.KeySpace))
	pubKey.SetType(int32(publicKey.Type))

	switch publicKey.Type {
	case rainslib.Ed25519:
		pubKey.SetKey(publicKey.Key.(ed25519.PublicKey))
	case rainslib.Ed448:
		log.Warn("Not yet supported")
	case rainslib.Ecdsa256:
		log.Warn("Not yet supported")
	case rainslib.Ecdsa384:
		log.Warn("Not yet supported")
	default:
		log.Warn("Unsupported public key type", "type", fmt.Sprintf("%T", publicKey.Type))
		return errors.New("Unsupported public key type")
	}

	return nil
}
