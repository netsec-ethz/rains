package message

import (
	"errors"
	"fmt"

	cbor "github.com/britram/borat"

	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

const (
	rainsTag = 0xE99BA8
)

// Message represents a Message
type Message struct {
	//Capabilities is a slice of capabilities or the hash thereof which the server originating the
	//message has.
	Capabilities []Capability
	//Token is used to identify a message
	Token token.Token
	//Content is a slice of
	Content []section.Section
	//Signatures authenticate the content of this message. An encoding of Message is signed by the infrastructure key of the originating server.
	Signatures []signature.Sig
}

func (rm *Message) UnmarshalCBOR(r *cbor.CBORReader) error {
	tag, err := r.ReadTag()
	if err != nil {
		return fmt.Errorf("failed to read tag: %v", err)
	}
	if tag != cbor.CBORTag(rainsTag) {
		return fmt.Errorf("expected tag for RAINS message but got: %v", tag)
	}
	m, err := r.ReadIntMapUntagged()
	if err != nil {
		return fmt.Errorf("failed to read map: %v", err)
	}

	if sigs, ok := m[0].([]interface{}); ok {
		rm.Signatures = make([]signature.Sig, len(sigs))
		for i, sig := range sigs {
			sigVal, ok := sig.([]interface{})
			if !ok {
				return errors.New("cbor zone signatures entry is not an array")
			}
			if err := rm.Signatures[i].UnmarshalArray(sigVal); err != nil {
				return err
			}
		}
	} //Signatures might be omitted

	if caps, ok := m[1].([]interface{}); ok {
		rm.Capabilities = make([]Capability, len(caps))
		for i, cap := range caps {
			c, ok := cap.(string)
			if !ok {
				return errors.New("cbor msg encoding of a capability array's element should be a string")
			}
			rm.Capabilities[i] = Capability(c)
		}
	} //capability might be omitted

	tok, ok := m[2].([]byte)
	if !ok || len(tok) != 16 {
		return errors.New("cbor message encoding of the token should be a byte array of length 16")
	}
	for i, val := range tok {
		rm.Token[i] = val
	}

	content, ok := m[23].([]interface{})
	if !ok {
		return errors.New("cbor msg encoding of the content should be an array")
	}
	for _, elem := range content {
		elem, ok := elem.([]interface{})
		if !ok {
			return errors.New("cbor msg encoding of a content array's entry should be an array")
		}
		t, ok := elem[0].(int)
		if !ok {
			return errors.New("cbor msg encoding of a section must start with its type")
		}
		val, ok := elem[1].(map[int]interface{})
		if !ok {
			return errors.New("cbor msg encoding of a section must end with a map")
		}
		switch t {
		case 1:
			a := &section.Assertion{}
			if err := a.UnmarshalMap(val); err != nil {
				return err
			}
			rm.Content = append(rm.Content, a)
		case 2:
			s := &section.Shard{}
			if err := s.UnmarshalMap(val); err != nil {
				return err
			}
			rm.Content = append(rm.Content, s)
		case 3:
			s := &section.Pshard{}
			if err := s.UnmarshalMap(val); err != nil {
				return err
			}
			rm.Content = append(rm.Content, s)
		case 4:
			z := &section.Zone{}
			if err := z.UnmarshalMap(val); err != nil {
				return err
			}
			rm.Content = append(rm.Content, z)
		case 5:
			q := &query.Name{}
			if err := q.UnmarshalMap(val); err != nil {
				return err
			}
			rm.Content = append(rm.Content, q)
		case 23:
			n := &section.Notification{}
			if err := n.UnmarshalMap(val); err != nil {
				return err
			}
			rm.Content = append(rm.Content, n)
		}
	}
	return nil
}

// MarshalCBOR writes the RAINS message to the provided writer.
// Implements the CBORMarshaler interface.
func (rm *Message) MarshalCBOR(w *cbor.CBORWriter) error {
	if err := w.WriteTag(cbor.CBORTag(rainsTag)); err != nil {
		return err
	}

	m := make(map[int]interface{})
	if len(rm.Signatures) > 0 {
		m[0] = rm.Signatures
	}

	if len(rm.Capabilities) > 0 {
		caps := make([]string, len(rm.Capabilities))
		for i, cap := range rm.Capabilities {
			caps[i] = string(cap)
		}
		m[1] = caps
	}
	m[2] = rm.Token[:]

	msgsect := make([][2]interface{}, 0)
	for _, sect := range rm.Content {
		switch sect.(type) {
		case *section.Assertion:
			msgsect = append(msgsect, [2]interface{}{1, sect})
		case *section.Shard:
			msgsect = append(msgsect, [2]interface{}{2, sect})
		case *section.Pshard:
			msgsect = append(msgsect, [2]interface{}{3, sect})
		case *section.Zone:
			msgsect = append(msgsect, [2]interface{}{4, sect})
		case *query.Name:
			msgsect = append(msgsect, [2]interface{}{5, sect})
		case *section.Notification:
			msgsect = append(msgsect, [2]interface{}{23, sect})
		default:
			return fmt.Errorf("unknown section type: %T", sect)
		}
	}
	m[23] = msgsect
	return w.WriteIntMap(m)
}

// Capability is a urn of a capability
type Capability string

const (
	//NoCapability is used when the server does not listen for any connections
	NoCapability Capability = "urn:x-rains:nocapability"
	//TLSOverTCP is used when the server listens for tls over tcp connections
	TLSOverTCP Capability = "urn:x-rains:tlssrv"
)
