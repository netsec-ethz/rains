package msgFramer

import (
	"bufio"
	"fmt"
	"io"
)

//NewLineFramer frames a rains message by adding a new line at the end of a message.
//CAUTION: When a new line is part of the message then this framer fails to correctly deframe the message from the stream.
type NewLineFramer struct {
	scanner *bufio.Scanner
}

//Frame adds a new line to the end of the message
func (f *NewLineFramer) Frame(msg []byte) ([]byte, error) {
	return append(msg, "\n"...), nil
}

//InitStream defines the stream from which deframe and data extract the information
func (f *NewLineFramer) InitStream(stream io.Reader) {
	f.scanner = bufio.NewScanner(stream)
}

//Deframe advances the NewLineFramer to the next rains message on the stream
func (f *NewLineFramer) Deframe() bool {
	if f.scanner == nil {
		fmt.Println("BAD1")
		return false
	}
	return f.scanner.Scan()
}

//Data extracts the current rains message from the stream
func (f *NewLineFramer) Data() []byte {
	if f.scanner == nil {
		fmt.Println("BAD2")
		return []byte{}
	}
	return f.scanner.Bytes()
}
