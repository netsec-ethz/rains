package protoParser

import (
	"rains/utils/testUtil"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	message := testUtil.GetMessage()
	p := ProtoParserAndFramer{}

	msg, err := p.Encode(message)
	if err != nil {
		t.Error("Failed to encode the message")
	}
	m, err := p.Decode(msg)
	if err != nil {
		t.Error("Failed to decode the message")
	}

	testUtil.CheckMessage(m, message, t)
}

func TestToken(t *testing.T) {
	message := testUtil.GetMessage()
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
