package token

import "encoding/hex"

//Token identifies a message
type Token [16]byte

//String implements Stringer interface
func (t Token) String() string {
	return hex.EncodeToString(t[:])
}
