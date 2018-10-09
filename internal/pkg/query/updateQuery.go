package query

import (
	"encoding/hex"
	"fmt"

	cbor "github.com/britram/borat"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/object"
)

type AssertionUpdate struct {
	Name       string
	HashType   algorithmTypes.Hash
	HashValue  []byte
	Expiration int64 //unix seconds
	Options    []Option
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (q *AssertionUpdate) UnmarshalMap(m map[int]interface{}) error {
	//TODO CFE to implement
	return nil
}

func (q *AssertionUpdate) MarshalCBOR(w *cbor.CBORWriter) error {
	//TODO CFE to implement
	return nil
}

//String implements Stringer interface
func (q *AssertionUpdate) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[NA=%s HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Name, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration, q.Options)
}

func (q *AssertionUpdate) Sort() {
	//TODO CFE to implement
}

type NegUpdate struct {
	Context     string
	Name        string
	ObjectTypes []object.Type
	HashType    algorithmTypes.Hash
	HashValue   []byte
	Expiration  int64 //unix seconds
	Options     []Option
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (q *NegUpdate) UnmarshalMap(m map[int]interface{}) error {
	//TODO CFE to implement
	return nil
}

func (q *NegUpdate) MarshalCBOR(w *cbor.CBORWriter) error {
	//TODO CFE to implement
	return nil
}

//String implements Stringer interface
func (q *NegUpdate) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[CTX=%s NA=%s OTYPE=%v HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Context, q.Name, q.ObjectTypes, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration,
		q.Options)
}

func (q *NegUpdate) Sort() {
	//TODO CFE to implement
}
