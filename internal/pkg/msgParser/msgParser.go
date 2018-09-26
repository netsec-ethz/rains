package msgParser

//RainsMsgParser can encode and decode RainsMessage.
//It is able to efficiently extract only the Token form an encoded RainsMessage
//It must always hold that: rainsMsg = Decode(Encode(rainsMsg)) && interface{} = Encode(Decode(interface{}))
type RainsMsgParser interface {
	//Decode extracts information from msg and returns a RainsMessage or an error
	Decode(msg []byte) (RainsMessage, error)

	//Encode encodes the given RainsMessage into a more compact representation.
	//If it was not able to encode msg an error is return indicating what the problem was.
	Encode(msg RainsMessage) ([]byte, error)

	//Token returns the extracted token from the given msg or an error
	Token(msg []byte) (Token, error)
}
