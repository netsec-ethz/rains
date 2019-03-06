package section

import (
	"encoding/hex"
	"errors"
	"fmt"

	cbor "github.com/britram/borat"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//Notification contains information about the notification
type Notification struct {
	Token token.Token
	Type  NotificationType
	Data  string
}

// UnmarshalMap unpacks a CBOR unmarshaled map to this object.
func (n *Notification) UnmarshalMap(m map[int]interface{}) error {
	tok, ok := m[2].([]byte)
	if !ok || len(tok) != 16 {
		return errors.New("cbor notification encoding of the token should be a byte array of length 16")
	}
	for i, val := range tok {
		n.Token[i] = val
	}
	if not, ok := m[21].(int); ok {
		n.Type = NotificationType(not)
	} else {
		return errors.New("cbor notification map does not contain type")
	}
	if data, ok := m[22].(string); ok {
		n.Data = string(data)
	} else {
		return errors.New("cbor notification map does not contain data")
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (n *Notification) MarshalCBOR(w *cbor.CBORWriter) error {
	m := make(map[int]interface{})
	m[2] = n.Token[:]
	m[21] = int(n.Type)
	m[22] = n.Data
	return w.WriteIntMap(m)
}

//Sort sorts the content of the notification lexicographically.
func (n *Notification) Sort() {
	//notification is already sorted (it does not contain a list of elements).
}

//CompareTo compares two notifications and returns 0 if they are equal, 1 if n is greater than
//notification and -1 if n is smaller than notification
func (n *Notification) CompareTo(notification *Notification) int {
	if comp := token.Compare(n.Token, notification.Token); comp != 0 {
		return comp
	} else if n.Type < notification.Type {
		return -1
	} else if n.Type > notification.Type {
		return 1
	} else if n.Data < notification.Data {
		return -1
	} else if n.Data > notification.Data {
		return 1
	}
	return 0
}

//String implements Stringer interface
func (n *Notification) String() string {
	if n == nil {
		return "Notification:nil"
	}
	return fmt.Sprintf("Notification:[TOK=%s TYPE=%d DATA=%s]",
		hex.EncodeToString(n.Token[:]), n.Type, n.Data)
}

//filterSigs returns only those signatures which are in the given keySpace
func filterSigs(signatures []signature.Sig, keySpace keys.KeySpaceID) []signature.Sig {
	sigs := []signature.Sig{}
	for _, sig := range signatures {
		if sig.KeySpace == keySpace {
			sigs = append(sigs, sig)
		}
	}
	return sigs
}

//NotificationType defines the type of a notification section
type NotificationType int

//go:generate stringer -type=NotificationType
const (
	NTHeartbeat          NotificationType = 100
	NTCapHashNotKnown    NotificationType = 399
	NTBadMessage         NotificationType = 400
	NTRcvInconsistentMsg NotificationType = 403
	NTNoAssertionsExist  NotificationType = 404
	NTMsgTooLarge        NotificationType = 413
	NTUnspecServerErr    NotificationType = 500
	NTServerNotCapable   NotificationType = 501
	NTNoAssertionAvail   NotificationType = 504
)
