package main

import (
	"fmt"
	"os"
	"rains/proto"
	"rains/rainslib"

	"errors"

	"strconv"

	log "github.com/inconshreveable/log15"
	capnp "zombiezen.com/go/capnproto2"
)

func main() {
	o := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	a := &rainslib.AssertionSection{Content: []rainslib.Object{o}, Context: ".", SubjectName: "ethz", SubjectZone: "ch"}
	sig := rainslib.Signature{KeySpace: rainslib.RainsKeySpace, Algorithm: rainslib.Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("Test")}
	m := rainslib.RainsMessage{Content: []rainslib.MessageSection{a}, Token: rainslib.GenerateToken(),
		Capabilities: []rainslib.Capability{rainslib.Capability("Test"), rainslib.Capability("Yes!")},
		Signatures:   []rainslib.Signature{sig}}

	//
	//Encode RAINS Message
	//
	/*msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		panic(err)
	}

	message, err := proto.NewRootRainsMessage(seg)
	if err != nil {
		panic(err)
	}
	tok := [16]byte(m.Token)
	message.SetToken(tok[:])
	fmt.Println(tok)
	//FIXME CFE use a switch statement
	obj, err := proto.NewObj(seg)
	obj.SetType(proto.ObjectType_oTIP4Addr)
	obj.Value().SetIp4(a.Content[0].Value.(string))
	//objList, err := proto.NewObj_List(seg, int32(len(a.Content)))

	assertion, err := proto.NewAssertionSection(seg)
	objList, err := assertion.NewContent(int32(len(a.Content)))
	objList.Set(0, obj)
	//assertion.SetContent(objList)
	assertion.SetContext(a.Context)
	assertion.SetSubjectName(a.SubjectName)
	assertion.SetSubjectZone(a.SubjectZone)
	section, err := proto.NewMessageSection(seg)
	section.SetAssertion(assertion)
	sectionList, err := proto.NewMessageSection_List(seg, int32(len(m.Content)))
	sectionList.Set(0, section)
	message.SetContent(sectionList)*/
	msg, err := EncodeMessage(m)
	if err != nil {
		log.Warn("BUG", "error", err)
	}

	//
	// Write the message to file.
	//
	file, err := os.Create("tmp/test.enc")
	if err != nil {
		fmt.Println("BAD ERROR")
	}

	err = capnp.NewEncoder(file).Encode(msg)
	if err != nil {
		panic(err)
	}

	//
	//READ message from file
	//
	file2, err := os.Open("tmp/test.enc")
	if err != nil {
		fmt.Println("BADERROR2")
	}
	input, err := capnp.NewDecoder(file2).Decode()
	if err != nil {
		panic(err)
	}

	//
	// Decode Rains Message
	//
	rootRainsMsg, err := proto.ReadRootRainsMessage(input)
	if err != nil {
		panic(err)
	}

	inputToken, _ := rootRainsMsg.Token()
	fmt.Println(inputToken)
	inputCaps, _ := rootRainsMsg.Capabilities()
	fmt.Println(inputCaps.At(1))
	inputSigs, _ := rootRainsMsg.Signatures()
	fmt.Println(inputSigs.At(0))
	/*inputSecList, _ := rootRainsMsg.Content()
	inputSection := inputSecList.At(0)
	switch inputSection.Which() {
	case proto.MessageSection_Which_assertion:
		inputAssertion, _ := inputSection.Assertion()
		fmt.Println(inputAssertion.Context())
		fmt.Println(inputAssertion.SubjectName())
		fmt.Println(inputAssertion.SubjectZone())
		list, _ := inputAssertion.Content()
		fmt.Println(list.At(0))
	}*/
}

//EncodeMessage uses capnproto to encode and frame the message. The message is then ready to be sent over the wire.
func EncodeMessage(m rainslib.RainsMessage) (*capnp.Message, error) {
	//Setup structure
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, err
	}
	message, err := proto.NewRootRainsMessage(seg)
	if err != nil {
		return nil, err
	}
	/*contentList, err := m.NewContent(int32(len(message.Content)))
	if err != nil {
		return nil, err
	}*/
	capabilitiesList, err := message.NewCapabilities(int32(len(m.Capabilities)))
	if err != nil {
		return nil, err
	}
	signatureList, err := message.NewSignatures(int32(len(m.Signatures)))
	if err != nil {
		return nil, err
	}

	//Add Content
	tok := [16]byte(m.Token)
	message.SetToken(tok[:])

	for i, c := range m.Capabilities {
		capabilitiesList.Set(i, string(c))
	}

	err = encodeSignatures(m.Signatures, &signatureList, seg)
	if err != nil {
		return nil, err
	}

	/*var ms proto.MessageSection
	for i, section := range m.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			ms, err = encodeAssertion(section)
		case *rainslib.ShardSection:
			ms, err = encodeShard(section)
		case *rainslib.ZoneSection:
			ms, err = encodeZone(section)
		case *rainslib.QuerySection:
			ms, err = encodeQuery(section)
		case *rainslib.NotificationSection:
			ms, err = encodeNotification(section)
		case *rainslib.AddressAssertionSection:
			ms, err = encodeAddressAssertion(section)
		case *rainslib.AddressZoneSection:
			ms, err = encodeAddressZone(section)
		case *rainslib.AddressQuerySection:
			ms, err = encodeAddressQuery(section)
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", section))
			return nil, errors.New("Unsupported section type")
		}
		if err != nil {
			return nil, err
		}
		contentList.Set(i, ms)
	}*/

	return msg, nil
}

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
	//TODO encode Object

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

	tok := [16]byte(q.Token)
	query.SetToken(tok[:])
	query.SetName(q.Name)
	query.SetContext(q.Context)
	query.SetExpires(q.Expires)
	query.SetType(int32(q.Type))

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
	return proto.MessageSection{}, nil
}

func encodeAddressZone(z *rainslib.AddressZoneSection, seg *capnp.Segment) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeAddressQuery(q *rainslib.AddressQuerySection, seg *capnp.Segment) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeSignatures(signatures []rainslib.Signature, list *proto.Signature_List, seg *capnp.Segment) error {
	for i, signature := range signatures {
		sig, err := proto.NewSignature(seg)
		if err != nil {
			return err
		}
		switch signature.KeySpace {
		case rainslib.RainsKeySpace:
			sig.SetKeySpace(proto.KeySpaceID_rainsKeySpace)
		default:
			log.Warn("Unsupported key space type", "type", fmt.Sprintf("%T", signature.KeySpace))
			return errors.New("Unsupported key space type")
		}

		switch signature.Algorithm {
		case rainslib.Ed25519:
			sig.SetAlgorithm(proto.SignatureAlgorithmType_ed25519)
		case rainslib.Ed448:
			sig.SetAlgorithm(proto.SignatureAlgorithmType_ed448)
		case rainslib.Ecdsa256:
			sig.SetAlgorithm(proto.SignatureAlgorithmType_ecdsa256)
		case rainslib.Ecdsa384:
			sig.SetAlgorithm(proto.SignatureAlgorithmType_ecdsa384)
		default:
			log.Warn("Unsupported signature algorithm type", "type", fmt.Sprintf("%T", signature.Algorithm))
			return errors.New("Unsupported signature algorithm type")
		}

		switch data := signature.Data.(type) {
		case []byte:
			sig.SetData(data)
		default:
			log.Warn("Unsupported signature data type", "type", fmt.Sprintf("%T", signature.Algorithm))
			return errors.New("Unsupported signature data type")

		}
		sig.SetValidSince(signature.ValidSince)
		sig.SetValidUntil(signature.ValidUntil)

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
				nameList, err := capnp.NewTextList(seg, int32(len(nameObject.Types)+1))
				if err != nil {
					return err
				}
				nameList.Set(0, nameObject.Name)
				for j, t := range nameObject.Types {
					nameList.Set(j+1, strconv.Itoa(int(t)))
				}
				obj.Value().SetName(nameList)
				continue
			}
			log.Warn("Type assertion failed. Expected ObjectName", "object", object.Value)
			return errors.New("Type assertion failed")

		case rainslib.OTIP6Addr:
			obj.Value().SetIp6(object.Value.(string))
		case rainslib.OTIP4Addr:
			obj.Value().SetIp4(object.Value.(string))
		case rainslib.OTRedirection:
			obj.Value().SetRedir(object.Value.(string))
		case rainslib.OTDelegation:
			publicKey, err := encodePublicKey(object.Value.(rainslib.PublicKey), seg)
			if err != nil {
				return err
			}
			obj.Value().SetDeleg(publicKey)
		case rainslib.OTNameset:
			obj.Value().SetNameset(string(object.Value.(rainslib.NamesetExpression)))
		case rainslib.OTCertInfo:
			if cert, ok := object.Value.(rainslib.CertificateObject); ok {
				c, err := proto.NewCertificateObject(seg)
				if err != nil {
					return err
				}
				c.SetData(cert.Data)
				switch cert.Type {
				case rainslib.PTUnspecified:
					c.SetType(proto.ProtocolType_pTUnspecified)
				case rainslib.PTTLS:
					c.SetType(proto.ProtocolType_pTTLS)
				default:
					log.Warn("Unsupported protocol type", "type", fmt.Sprintf("%T", cert.Type))
					return errors.New("Unsupported protocol type")
				}
				switch cert.HashAlgo {
				case rainslib.NoHashAlgo:
					c.SetHashAlgo(proto.HashAlgorithmType_noHashAlgo)
				case rainslib.Sha256:
					c.SetHashAlgo(proto.HashAlgorithmType_sha256)
				case rainslib.Sha384:
					c.SetHashAlgo(proto.HashAlgorithmType_sha384)
				case rainslib.Sha512:
					c.SetHashAlgo(proto.HashAlgorithmType_sha512)
				default:
					log.Warn("Unsupported hash algo type", "type", fmt.Sprintf("%T", cert.HashAlgo))
					return errors.New("Unsupported hash algo type")
				}
				switch cert.Usage {
				case rainslib.CUTrustAnchor:
					c.SetUsage(proto.CertificateUsage_cUTrustAnchor)
				case rainslib.CUEndEntity:
					c.SetUsage(proto.CertificateUsage_cUEndEntity)
				default:
					log.Warn("Unsupported cert usage type", "type", fmt.Sprintf("%T", cert.Usage))
					return errors.New("Unsupported cert usage type")
				}
				obj.Value().SetCert(c)
				continue
			}
			log.Warn("Type assertion failed. Expected CertificateObject", "object", object.Value)
			return errors.New("Type assertion failed")
		case rainslib.OTServiceInfo:
			if servInfo, ok := object.Value.(rainslib.ServiceInfo); ok {
				si, err := proto.NewServiceInfo(seg)
				if err != nil {
					return err
				}
				si.SetName(servInfo.Name)
				si.SetPort(servInfo.Port)
				si.SetPriority(uint32(servInfo.Priority))
				obj.Value().SetService(si)
				continue
			}
			log.Warn("Type assertion failed. Expected ServiceInfo", "object", object.Value)
			return errors.New("Type assertion failed")
		case rainslib.OTRegistrar:
			obj.Value().SetRegr(object.Value.(string))
		case rainslib.OTRegistrant:
			obj.Value().SetRegt(object.Value.(string))
		case rainslib.OTInfraKey:
			publicKey, err := encodePublicKey(object.Value.(rainslib.PublicKey), seg)
			if err != nil {
				return err
			}
			obj.Value().SetInfra(publicKey)
		case rainslib.OTExtraKey:
			publicKey, err := encodePublicKey(object.Value.(rainslib.PublicKey), seg)
			if err != nil {
				return err
			}
			obj.Value().SetExtra(publicKey)
		default:
			log.Warn("Unsupported object type", "type", fmt.Sprintf("%T", object.Type))
			return errors.New("Unsupported object type")
		}
		list.Set(i, obj)
	}
	return nil
}

func encodePublicKey(publicKey rainslib.PublicKey, seg *capnp.Segment) (proto.PublicKey, error) {
	pubKey, err := proto.NewPublicKey(seg)
	if err != nil {
		return proto.PublicKey{}, err
	}
	pubKey.SetValidSince(publicKey.ValidSince)
	pubKey.SetValidUntil(publicKey.ValidUntil)

	switch publicKey.KeySpace {
	case rainslib.RainsKeySpace:
		pubKey.SetKeySpace(proto.KeySpaceID_rainsKeySpace)
	default:
		log.Warn("Unsupported key space type", "type", fmt.Sprintf("%T", publicKey.KeySpace))
		return proto.PublicKey{}, errors.New("Unsupported key space type")
	}

	switch publicKey.Type {
	case rainslib.Ed25519:
		pubKey.SetType(proto.SignatureAlgorithmType_ed25519)
		pubKey.SetKey(publicKey.Key.([]byte))
	case rainslib.Ed448:
		pubKey.SetType(proto.SignatureAlgorithmType_ed448)
		log.Warn("Not yet supported")
	case rainslib.Ecdsa256:
		pubKey.SetType(proto.SignatureAlgorithmType_ecdsa256)
		log.Warn("Not yet supported")
	case rainslib.Ecdsa384:
		pubKey.SetType(proto.SignatureAlgorithmType_ecdsa384)
		log.Warn("Not yet supported")
	default:
		log.Warn("Unsupported signature algorithm type", "type", fmt.Sprintf("%T", publicKey.Type))
		return proto.PublicKey{}, errors.New("Unsupported signature algorithm type")
	}

	return pubKey, nil
}
