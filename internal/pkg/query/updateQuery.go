package query

import (
	"encoding/hex"
	"fmt"

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

//String implements Stringer interface
func (q *AssertionUpdate) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[NA=%s HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Name, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration, q.Options)
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

//String implements Stringer interface
func (q *NegUpdate) String() string {
	if q == nil {
		return "AssertionUpdateQuery:nil"
	}
	return fmt.Sprintf("AssertionUpdateQuery:[CTX=%s NA=%s OTYPE=%v HTYPE=%v VAL=%s EXP=%d OPT=%v]",
		q.Context, q.Name, q.ObjectTypes, q.HashType, hex.EncodeToString(q.HashValue), q.Expiration,
		q.Options)
}
