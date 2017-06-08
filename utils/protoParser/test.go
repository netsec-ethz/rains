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
	inputSecList, _ := rootRainsMsg.Content()
	inputSection := inputSecList.At(0)
	switch inputSection.Which() {
	case proto.MessageSection_Which_assertion:
		inputAssertion, _ := inputSection.Assertion()
		fmt.Println(inputAssertion.Context())
		fmt.Println(inputAssertion.SubjectName())
		fmt.Println(inputAssertion.SubjectZone())
		list, _ := inputAssertion.Content()
		fmt.Println(list.At(0))
	}
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
	contentList, err := message.NewContent(int32(len(m.Content)))
	if err != nil {
		return nil, err
	}
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

	var ms proto.MessageSection
	for i, section := range m.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			ms, err = encodeAssertion(section, seg)
		case *rainslib.ShardSection:
			ms, err = encodeShard(section, seg)
		case *rainslib.ZoneSection:
			ms, err = encodeZone(section, seg)
		case *rainslib.QuerySection:
			ms, err = encodeQuery(section, seg)
		case *rainslib.NotificationSection:
			ms, err = encodeNotification(section, seg)
		case *rainslib.AddressAssertionSection:
			ms, err = encodeAddressAssertion(section, seg)
		case *rainslib.AddressZoneSection:
			ms, err = encodeAddressZone(section, seg)
		case *rainslib.AddressQuerySection:
			ms, err = encodeAddressQuery(section, seg)
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", section))
			return nil, errors.New("Unsupported section type")
		}
		if err != nil {
			return nil, err
		}
		contentList.Set(i, ms)
	}

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

	sa, err := encodeSubjectAddress(a.SubjectAddr, seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	assertion.SetSubjectAddr(sa)

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

	sa, err := encodeSubjectAddress(z.SubjectAddr, seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	zone.SetSubjectAddr(sa)

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

	tok := [16]byte(q.Token)
	query.SetToken(tok[:])
	query.SetContext(q.Context)
	query.SetExpires(q.Expires)
	query.SetTypes(int32(q.Types))

	qoList, err := capnp.NewInt32List(seg, int32(len(q.Options)))
	if err != nil {
		return proto.MessageSection{}, err
	}
	for i, opt := range q.Options {
		qoList.Set(i, int32(opt))
	}
	query.SetOptions(qoList)

	sa, err := encodeSubjectAddress(q.SubjectAddr, seg)
	if err != nil {
		return proto.MessageSection{}, err
	}
	query.SetSubjectAddr(sa)
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
				c.SetType(int32(cert.Type))
				c.SetHashAlgo(int32(cert.HashAlgo))
				c.SetUsage(int32(cert.Usage))
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
	pubKey.SetKeySpace(int32(publicKey.KeySpace))
	pubKey.SetType(int32(publicKey.Type))

	switch publicKey.Type {
	case rainslib.Ed25519:
		pubKey.SetKey(publicKey.Key.([]byte))
	case rainslib.Ed448:
		log.Warn("Not yet supported")
	case rainslib.Ecdsa256:
		log.Warn("Not yet supported")
	case rainslib.Ecdsa384:
		log.Warn("Not yet supported")
	default:
		log.Warn("Unsupported signature algorithm type", "type", fmt.Sprintf("%T", publicKey.Type))
		return proto.PublicKey{}, errors.New("Unsupported signature algorithm type")
	}

	return pubKey, nil
}

func encodeSubjectAddress(subjectAddress rainslib.SubjectAddr, seg *capnp.Segment) (proto.SubjectAddr, error) {
	sa, err := proto.NewSubjectAddr(seg)
	if err != nil {
		return proto.SubjectAddr{}, err
	}
	sa.SetAddress(subjectAddress.Address)
	sa.SetAddressFamily(subjectAddress.AddressFamily)
	sa.SetPrefixLength(uint32(subjectAddress.PrefixLength))
	return sa, nil
}

//DecodeMessage uses capnproto to decode and deframe the message.
func DecodeMessage(m *capnp.Message) (rainslib.RainsMessage, error) {
	message := rainslib.RainsMessage{}
	msg, err := proto.ReadRootRainsMessage(m)
	if err != nil {
		panic(err)
	}

	tok, err := msg.Token()
	if err != nil {
		log.Warn("Could not decode token", "error", err)
		return rainslib.RainsMessage{}, err
	}
	message.Token.Update(tok)

	capabilities, err := msg.Capabilities()
	if err != nil {
		log.Warn("Could not decode capabilities", "error", err)
		return rainslib.RainsMessage{}, err
	}
	for i := 0; i < capabilities.Len(); i++ {
		c, err := capabilities.At(i)
		if err != nil {
			log.Warn("Could not decode capability at", "position", i, "error", err)
			return rainslib.RainsMessage{}, err
		}
		message.Capabilities = append(message.Capabilities, rainslib.Capability(c))
	}

	sigList, err := msg.Signatures()
	if err != nil {
		log.Warn("Could not decode signature list", "error", err)
		return rainslib.RainsMessage{}, err
	}
	message.Signatures, err = decodeSignatures(sigList)
	if err != nil {
		return rainslib.RainsMessage{}, err
	}

	contentList, err := msg.Content()
	if err != nil {
		return rainslib.RainsMessage{}, err
	}
	message.Content, err = decodeContent(contentList)
	if err != nil {
		return rainslib.RainsMessage{}, err
	}
	return message, nil
}

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
		log.Warn("Was not able to decode zone", "error", err)
		return nil, err
	}

	assertion.SubjectName, err = a.SubjectName()
	if err != nil {
		log.Warn("Was not able to decode name", "error", err)
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

	//FIXME CFE decode object

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
		log.Warn("Was not able to decode zone", "error", err)
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
		log.Warn("Was not able to decode zone", "error", err)
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

	query.Expires = q.Expires()
	query.Type = rainslib.ObjectType(q.Type())

	tok, err := q.Token()
	if err != nil {
		log.Warn("Could not decode token", "error", err)
		return nil, err
	}
	query.Token.Update(tok)

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
	notification.Token.Update(tok)

	notification.Data, err = n.Data()
	if err != nil {
		log.Warn("Was not able to decode data", "error", err)
		return nil, err
	}
	return &notification, nil
}

func decodeAddressAssertion(a proto.AddressAssertionSection) (*rainslib.AddressAssertionSection, error) {
	assertion := rainslib.AddressAssertionSection{}

	addr, err := a.SubjectAddr()
	if err != nil {
		log.Warn("Was not able to decode subjectAddr", "error", err)
		return nil, err
	}
	assertion.SubjectAddr, err = decodeSubjectAddress(addr)
	if err != nil {
		log.Warn("Could not decode subjectAddr", "error", err)
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

	//FIXME decode objects (content)

	return &assertion, nil
}

func decodeAddressZone(z proto.AddressZoneSection) (*rainslib.AddressZoneSection, error) {
	zone := rainslib.AddressZoneSection{}

	addr, err := z.SubjectAddr()
	if err != nil {
		log.Warn("Was not able to decode subjectAddr", "error", err)
		return nil, err
	}
	zone.SubjectAddr, err = decodeSubjectAddress(addr)
	if err != nil {
		log.Warn("Could not decode subjectAddr", "error", err)
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
	query.Types = rainslib.ObjectType(q.Types())

	addr, err := q.SubjectAddr()
	if err != nil {
		log.Warn("Was not able to decode subjectAddr", "error", err)
		return nil, err
	}
	query.SubjectAddr, err = decodeSubjectAddress(addr)
	if err != nil {
		log.Warn("Could not decode subjectAddr", "error", err)
		return nil, err
	}

	tok, err := q.Token()
	if err != nil {
		log.Warn("Could not decode token", "error", err)
		return nil, err
	}
	query.Token.Update(tok)

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

func decodeSubjectAddress(addr proto.SubjectAddr) (rainslib.SubjectAddr, error) {
	subjectAddr := rainslib.SubjectAddr{}
	var err error

	subjectAddr.PrefixLength = uint(addr.PrefixLength())

	subjectAddr.AddressFamily, err = addr.AddressFamily()
	if err != nil {
		log.Warn("Could not decode address family", "error", err)
		return rainslib.SubjectAddr{}, err
	}

	subjectAddr.Address, err = addr.Address()
	if err != nil {
		log.Warn("Could not decode address", "error", err)
		return rainslib.SubjectAddr{}, err
	}

	return subjectAddr, nil
}
