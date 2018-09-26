package msgParser

import (
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//RainsMsgParser can encode and decode Message.
//It is able to efficiently extract only the Token form an encoded Message
//It must always hold that: rainsMsg = Decode(Encode(rainsMsg)) && interface{} = Encode(Decode(interface{}))
type RainsMsgParser interface {
	//Decode extracts information from msg and returns a Message or an error
	Decode(msg []byte) (message.Message, error)

	//Encode encodes the given Message into a more compact representation.
	//If it was not able to encode msg an error is return indicating what the problem was.
	Encode(msg message.Message) ([]byte, error)

	//Token returns the extracted token from the given msg or an error
	Token(msg []byte) (token.Token, error)
}
