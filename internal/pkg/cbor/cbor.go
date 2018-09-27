package cbor

import (
	"io"

	"github.com/britram/borat"
)

//Writer defines all functions necessary to encode a message or section in cbor
type Writer interface {
	Marshal(x interface{}) error
	WriteIntMap(m map[int]interface{}) error
	WriteTag(t borat.CBORTag) error
	WriteArray(a []interface{}) error
}

//Reader defines all functions necessary to decode a message or section encoded in cbor
type Reader interface {
	Unmarshal(x interface{}) error
	ReadTag() (borat.CBORTag, error)
	ReadIntMapUntagged() (map[int]interface{}, error)
}

//NewWriter returns a new cbor writer which writes to out.
func NewWriter(out io.Writer) Writer {
	return borat.NewCBORWriter(out)
}

//NewWriter returns a new cbor writer which writes to out.
func NewReader(in io.Reader) Reader {
	return borat.NewCBORReader(in)
}

//RainsTag returns the rains cbor tag.
func RainsTag() borat.CBORTag {
	return borat.CBORTag(0xE99BA8)
}
