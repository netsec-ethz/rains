package protoParser

import (
	"errors"
	"fmt"
	"io"
	"rains/proto"
	"rains/rainslib"
	"strconv"

	log "github.com/inconshreveable/log15"
	capnp "zombiezen.com/go/capnproto2"
)

//ProtoParserAndFramer contains methods to encode, frame, decode and deframe rainsMessages.
type ProtoParserAndFramer struct {
	decoder *capnp.Decoder
	encoder *capnp.Encoder
	data    *capnp.Message
}

func init() {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(h)
}

//Frame takes a message and adds a frame (if it not already has one) and send the framed message to the streamWriter defined in InitStream()
func (p *ProtoParserAndFramer) Frame(msg []byte) error {
	message, err := capnp.Unmarshal(msg)
	if err != nil {
		return err
	}
	err = p.encoder.Encode(message)
	return err
}

//InitStreams defines 2 streams. Deframe() and Data() are extracting the information from streamReader and Frame() is sending the data to streamWriter.
//If a stream is readable and writable it is possible that streamReader = streamWriter
func (p *ProtoParserAndFramer) InitStreams(streamReader io.Reader, streamWriter io.Writer) {
	p.decoder = capnp.NewDecoder(streamReader)
	p.encoder = capnp.NewEncoder(streamWriter)
}

//Deframe extracts the next frame from the streamReader defined in InitStream().
//It blocks until it encounters the delimiter.
//It returns false when the stream was not initialized or is already closed.
//The data is available through Data
func (p *ProtoParserAndFramer) Deframe() bool {
	msg, err := p.decoder.Decode()
	if err != nil {
		log.Warn("Was not able to decode msg", "error", err)
		return false
	}
	p.data = msg
	return true
}

//Data contains the frame read from the stream by Deframe
func (p *ProtoParserAndFramer) Data() []byte {
	if data, err := p.data.Marshal(); err == nil {
		return data
	}
	log.Warn("Was not able to marshal protoMessage", "message", p.data)
	return []byte{}
}

//Encode uses capnproto to encode and frame the message. The message is then ready to be sent over the wire.
func (p *ProtoParserAndFramer) Encode(m rainslib.RainsMessage) ([]byte, error) {
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

	return msg.Marshal()

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
		pkey := publicKey.Key.(rainslib.Ed25519PublicKey)
		pubKey.SetKey(pkey[:])
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

//Decode uses capnproto to decode and deframe the message.
func (p *ProtoParserAndFramer) Decode(input []byte) (rainslib.RainsMessage, error) {
	message := rainslib.RainsMessage{}
	m, err := capnp.Unmarshal(input)
	if err != nil {
		return rainslib.RainsMessage{}, err
	}
	msg, err := proto.ReadRootRainsMessage(m)
	if err != nil {
		return rainslib.RainsMessage{}, err
	}

	tok, err := msg.Token()
	if err != nil {
		log.Warn("Could not decode token", "error", err)
		return rainslib.RainsMessage{}, err
	}
	if len(tok) != 16 {
		log.Warn("Length of token is not 16", "token", tok, "length", len(tok))
		return rainslib.RainsMessage{}, errors.New("Length of token is not 16")
	}
	copy(message.Token[:], tok)

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
	length := 16
	if len(tok) < 16 {
		length = len(tok)
	}
	copy(query.Token[:], tok[:length])

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
	length := 16
	if len(tok) < 16 {
		length = len(tok)
	}
	copy(query.Token[:], tok[:length])

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
			nameList, err := obj.Value().Name()
			if err != nil {
				log.Warn("Was not able to decode name object value", "error", err)
				return nil, err
			}
			nameObject := rainslib.NameObject{}
			nameObject.Name, err = nameList.At(0)
			if err != nil {
				log.Warn("Was not able to decode name object value", "error", err)
				return nil, err
			}
			for j := 1; j < nameList.Len(); j++ {
				t, err := nameList.At(j)
				if err != nil {
					log.Warn("Was not able to decode name object value", "error", err)
					return nil, err
				}
				objType, err := strconv.Atoi(t)
				if err != nil {
					log.Warn("Was not able to convert string to int (objectType)", "error", err)
					return nil, err
				}
				nameObject.Types = append(nameObject.Types, rainslib.ObjectType(objType))
			}
			object.Value = nameObject
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
			c, err := obj.Value().Cert()
			if err != nil {
				log.Warn("Was not able to decode cert object value", "error", err)
				return nil, err
			}
			cert := rainslib.CertificateObject{
				Type:     rainslib.ProtocolType(c.Type()),
				HashAlgo: rainslib.HashAlgorithmType(c.HashAlgo()),
				Usage:    rainslib.CertificateUsage(c.Usage()),
			}
			cert.Data, err = c.Data()
			if err != nil {
				log.Warn("Was not able to decode cert data value", "error", err)
				return nil, err
			}
			object.Value = cert
		case proto.Obj_value_Which_service:
			si, err := obj.Value().Service()
			if err != nil {
				log.Warn("Was not able to decode service info object value", "error", err)
				return nil, err
			}
			serviceInfo := rainslib.ServiceInfo{
				Port:     uint16(si.Port()),
				Priority: uint(si.Priority()),
			}

			serviceInfo.Name, err = si.Name()
			if err != nil {
				log.Warn("Was not able to decode service info name", "error", err)
				return nil, err
			}
			object.Value = serviceInfo
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
				log.Warn("Was not able to decode delegation object value", "error", err)
				return nil, err
			}
			object.Value, err = decodePublicKey(pkey)
			if err != nil {
				return nil, err
			}
		case proto.Obj_value_Which_extra:
			pkey, err := obj.Value().Extra()
			if err != nil {
				log.Warn("Was not able to decode delegation object value", "error", err)
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
	var err error
	switch publicKey.Type {
	case rainslib.Ed25519:
		publicKey.Key, err = pkey.Key()
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

//Token returns the extracted token from the given msg or an error
func (p *ProtoParserAndFramer) Token(m []byte) (rainslib.Token, error) {
	token := rainslib.Token{}
	message, err := capnp.Unmarshal(m)
	if err != nil {
		return token, nil
	}
	msg, err := proto.ReadRootRainsMessage(message)
	if err != nil {
		return token, err
	}

	tok, err := msg.Token()
	if err != nil {
		log.Warn("Could not decode token", "error", err)
		return token, err
	}
	if len(tok) != 16 {
		log.Warn("Length of token is not 16", "token", tok, "length", len(tok))
		return token, errors.New("Length of token is not 16")
	}

	copy(token[:], tok)
	return token, nil
}
