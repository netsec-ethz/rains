package protoParser

import (
	"errors"
	"fmt"
	"io"
	"rains/proto"
	"rains/rainslib"
	"time"

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

//InitStreams defines 2 streams. Deframe() and Data() are extracting the information from streamReader and Frame() is sending the data to streamWriter.
//If a stream is readable and writable it is possible that streamReader = streamWriter
func (p *ProtoParserAndFramer) InitStreams(streamReader io.Reader, streamWriter io.Writer) {
	p.decoder = capnp.NewDecoder(streamReader)
	p.encoder = capnp.NewEncoder(streamWriter)
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

//DeFrame extracts the next frame from the streamReader defined in InitStream().
//It blocks until it encounters the delimiter.
//It returns false when the stream was not initialized, an error occurred while reading or is already closed.
//The data is available through Data
func (p *ProtoParserAndFramer) DeFrame() bool {
	for {
		var err error
		p.data, err = p.decoder.Decode()
		if err != nil {
			if err == io.EOF {
				//FIXME determine when a connection is closed and then break out of this loop
				//polling without backoff is probably too aggressive. CPU load is very high if we do not sleep here
				time.Sleep(50 * time.Millisecond)
				continue
			}
			log.Warn("Was not able to decode msg", "error", err)
			return false
		}
		return true
	}
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
