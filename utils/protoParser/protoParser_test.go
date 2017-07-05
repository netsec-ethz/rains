package protoParser

import (
	"rains/rainslib"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	message := rainslib.GetMessage()
	p := ProtoParserAndFramer{}

	msg, err := p.Encode(message)
	if err != nil {
		t.Error("Failed to encode the message")
	}
	m, err := p.Decode(msg)
	if err != nil {
		t.Error("Failed to decode the message")
	}

	rainslib.CheckMessage(m, message, t)
}

func TestToken(t *testing.T) {
	message := rainslib.GetMessage()
	p := ProtoParserAndFramer{}

	msg, err := p.Encode(message)
	if err != nil {
		t.Error("Failed to encode the message")
	}
	token, err := p.Token(msg)
	if token != message.Token {
		t.Error("extracted token is different", "expected", message.Token, "actual", token)
	}
}
