package main

import (
	"fmt"
	"os"
	"rains/proto"
	"rains/rainslib"

	"errors"

	log "github.com/inconshreveable/log15"
	capnp "zombiezen.com/go/capnproto2"
)

func main() {
	o := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	a := rainslib.AssertionSection{Content: []rainslib.Object{o}, Context: ".", SubjectName: "ethz", SubjectZone: "ch"}
	m := rainslib.RainsMessage{Content: []rainslib.MessageSection{a}, Token: rainslib.GenerateToken()}

	//
	//Encode RAINS Message
	//
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
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
	message.SetContent(sectionList)

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
func EncodeMessage(message rainslib.RainsMessage) (*capnp.Message, error) {
	//Setup structure
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, err
	}
	m, err := proto.NewRootRainsMessage(seg)
	if err != nil {
		return nil, err
	}
	contentList, err := m.NewContent(int32(len(message.Content)))
	if err != nil {
		return nil, err
	}
	capabilitiesList, err := m.NewCapabilities(int32(len(message.Capabilities)))
	if err != nil {
		return nil, err
	}
	signatureList, err := m.NewSignatures(int32(len(message.Signatures)))
	if err != nil {
		return nil, err
	}

	//Add Content
	tok := [16]byte(message.Token)
	m.SetToken(tok[:])

	var ms proto.MessageSection
	for i, section := range message.Content {
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
	}

	for i, c := range message.Capabilities {
		capabilitiesList.Set(i, string(c))
	}

	err = encodeSignature(message.Signatures, &signatureList, seg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func encodeAssertion(a *rainslib.AssertionSection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeShard(s *rainslib.ShardSection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeZone(z *rainslib.ZoneSection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeQuery(q *rainslib.QuerySection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeNotification(n *rainslib.NotificationSection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeAddressAssertion(a *rainslib.AddressAssertionSection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeAddressZone(z *rainslib.AddressZoneSection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeAddressQuery(q *rainslib.AddressQuerySection) (proto.MessageSection, error) {
	return proto.MessageSection{}, nil
}

func encodeSignature(signatures []rainslib.Signature, list *proto.Signature_List, seg *capnp.Segment) error {
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
