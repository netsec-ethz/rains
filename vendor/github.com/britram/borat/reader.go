package borat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"time"
)

var (
	CBORTypeReadError = errors.New("invalid CBOR type for typed read")
	InvalidCBORError  = errors.New("invalid CBOR")
	// UnsupportedTypeReadError is an explicit error for types we do not support.
	// This is different to encountering something which is not in the RFC.
	UnsupportedTypeReadError = errors.New("unsupported type encountered in read")
)

// CBORReader provides functionality to decode encoded CBOR to structures or to
// manually read elements out of a byte slice.
type CBORReader struct {
	in           io.Reader
	pushback     []byte
	pushed       uint
	messageLimit uint64 // Implement a maximum message size.
	regTags      map[CBORTag]reflect.Type
}

// NewCBORReader creates a new instance of the CBORReader.
func NewCBORReader(in io.Reader) *CBORReader {
	r := new(CBORReader)
	r.in = in
	r.regTags = make(map[CBORTag]reflect.Type)
	return r
}

// RegisterCBORTag configures a mapping from a CBOR tag to a specific struct.
func (r *CBORReader) RegisterCBORTag(tag CBORTag, inst interface{}) error {
	if _, ok := r.regTags[tag]; ok {
		return fmt.Errorf("tag %d is already registered", tag)
	}
	r.regTags[tag] = reflect.TypeOf(inst)
	return nil
}

func (r *CBORReader) readType() (byte, error) {
	b := make([]byte, 1)
	if r.pushed > 0 {
		b[0] = r.pushback[0]
		r.pushback = r.pushback[1:]
		r.pushed--
	} else {
		_, err := io.ReadAtLeast(r.in, b, 1)
		if err != nil {
			return 0, err
		}
	}
	return b[0], nil
}

func (r *CBORReader) pushbackType(pushback byte) {
	r.pushback = append(r.pushback, pushback)
	r.pushed++
}

func (r *CBORReader) readBasicUnsigned(mt byte) (uint64, byte, bool, error) {
	// read the first byte to see how much int to read

	// byte 0 is the CBOR type
	ct, err := r.readType()
	if err != nil {
		return 0, 0, false, err
	}

	// check for negative if this is a straight integer
	var neg bool
	if mt == majorUnsigned {
		switch ct & majorSelect {
		case majorUnsigned:
			neg = false
		case majorNegative:
			neg = true
		default:
			// type mismatch, push back
			r.pushbackType(ct)
			return 0, ct, false, CBORTypeReadError
		}
	} else {
		if ct&majorSelect != mt {
			// type mismatch, push back
			r.pushbackType(ct)
			return 0, ct, false, CBORTypeReadError
		}
	}

	// Type of <= 23 is used for storing small integers directly.
	// 24 - 27 represent 1, 2, 4, or 8 byte integers respectively.
	var u uint64
	switch {
	case ct&majorMask <= 23:
		u = uint64(ct & majorMask)

	case ct&majorMask == 24:
		b := make([]byte, 1)
		_, err := io.ReadAtLeast(r.in, b, 1)
		if err != nil {
			return 0, 0, false, err
		}
		u = uint64(b[0])

	case ct&majorMask == 25:
		b := make([]byte, 2)
		_, err := io.ReadAtLeast(r.in, b, 2)
		if err != nil {
			return 0, 0, false, err
		}
		u = uint64(binary.BigEndian.Uint16(b))

	case ct&majorMask == 26:
		b := make([]byte, 4)
		_, err := io.ReadAtLeast(r.in, b, 4)
		if err != nil {
			return 0, 0, false, err
		}
		u = uint64(binary.BigEndian.Uint32(b))

	case ct&majorMask == 27:
		b := make([]byte, 8)
		_, err := io.ReadAtLeast(r.in, b, 8)
		if err != nil {
			return 0, 0, false, err
		}
		u = uint64(binary.BigEndian.Uint64(b))

	default:
		return 0, 0, false, InvalidCBORError
	}

	return u, ct, neg, nil
}

// ReadInt reads a numerical type and sets the sign accordingly.
func (r *CBORReader) ReadInt() (int, error) {
	var i int
	u, _, neg, err := r.readBasicUnsigned(majorUnsigned)
	if err != nil {
		return 0, err
	}

	// negate if necessary and return
	if neg {
		i = -1 - int(u)
	} else {
		i = int(u)
	}

	return i, nil
}

// ReadUint reads an numerical type but discards the sign information if any.
func (r *CBORReader) ReadUint() (uint64, error) {
	if u, _, _, err := r.readBasicUnsigned(majorUnsigned); err != nil {
		return 0, err
	} else {
		return u, nil
	}
}

// ReadTag reads a CBOR tag type.
func (r *CBORReader) ReadTag() (CBORTag, error) {
	u, _, _, err := r.readBasicUnsigned(majorTag)
	if err != nil {
		return 0, err
	}

	return CBORTag(u), nil
}

// ReadFloat reads a floating point type.
func (r *CBORReader) ReadFloat() (float64, error) {
	u, ct, _, err := r.readBasicUnsigned(majorOther)
	if err != nil {
		return 0, err
	}

	var f float64
	switch ct {
	case majorOther | 25:
		// FIXME: float16 is not supported right now.
		return 0, UnsupportedTypeReadError
	case majorOther | 26:
		// 32 bit float.
		f = float64(math.Float32frombits(uint32(u)))
	case majorOther | 27:
		// 64 bit float.
		f = math.Float64frombits(u)
	default:
		r.pushbackType(ct)
		return 0, CBORTypeReadError
	}

	return f, nil
}

// ReadBytes reads the byte array type.
func (r *CBORReader) ReadBytes() ([]byte, error) {
	// read length
	u, _, _, err := r.readBasicUnsigned(majorBytes)
	if err != nil {
		return nil, err
	}

	// read u bytes and return them
	b := make([]byte, u)
	_, err = io.ReadAtLeast(r.in, b, int(u))
	if err != nil {
		return nil, err
	}

	return b, nil
}

// ReadString reads a string type.
func (r *CBORReader) ReadString() (string, error) {
	// read length
	u, _, _, err := r.readBasicUnsigned(majorString)
	if err != nil {
		return "", err
	}

	// empty string special case.
	if u == 0 {
		return "", nil
	}

	// read u bytes and return them as a string
	b := make([]byte, u)
	_, err = io.ReadAtLeast(r.in, b, int(u))
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// ReadArray reads an arbitrary array type.
func (r *CBORReader) ReadArray() ([]TaggedElement, error) {
	// read length
	u, _, _, err := r.readBasicUnsigned(majorArray)
	if err != nil {
		return nil, err
	}

	arraylen := int(u)

	// create an output value
	out := make([]TaggedElement, arraylen)

	// now read that many values
	for i := 0; i < arraylen; i++ {
		var elem TaggedElement
		v, err := r.Read()
		if err != nil {
			return nil, err
		}
		if tag, ok := v.(CBORTag); ok {
			// The thing we have read here is a CBOR tag, so we have to read again to get the tagged element.
			te, err := r.Read()
			if err != nil {
				return nil, err
			}
			elem.Tag = tag
			elem.Value = te
		} else {
			elem.Value = v
		}
		out[i] = elem
	}

	return out, nil
}

// ReadStringArray reads an array of strings.
func (r *CBORReader) ReadStringArray() ([]string, error) {
	// read length
	u, _, _, err := r.readBasicUnsigned(majorArray)
	if err != nil {
		return nil, err
	}

	arraylen := int(u)

	// create an output value
	out := make([]string, arraylen)

	// now read that many values
	for i := 0; i < arraylen; i++ {
		v, err := r.ReadString()
		if err != nil {
			return nil, err
		}
		out[i] = v
	}

	return out, nil
}

// ReadIntArray reads an array of integers.
func (r *CBORReader) ReadIntArray() ([]int, error) {
	// read length
	u, _, _, err := r.readBasicUnsigned(majorArray)
	if err != nil {
		return nil, err
	}

	arraylen := int(u)

	// create an output value
	out := make([]int, arraylen)

	// now read as many values as there should be
	for i := 0; i < arraylen; i++ {
		v, err := r.ReadInt()
		if err != nil {
			return nil, err
		}
		out[i] = v
	}

	return out, nil
}

// ReadStringMap reads a CBOR map type.
func (r *CBORReader) ReadStringMap() (map[string]TaggedElement, error) {
	// read length
	u, _, _, err := r.readBasicUnsigned(majorMap)
	if err != nil {
		return nil, err
	}

	maplen := int(u)

	// create an output value
	out := make(map[string]TaggedElement)

	// now read as many key/value pairs as there should be
	for i := 0; i < maplen; i++ {
		var ks string
		k, err := r.Read()
		if err != nil {
			return nil, err
		}
		switch k.(type) {
		case string:
			ks = k.(string)
		default:
			ks = fmt.Sprintf("%v", k)
		}
		var res TaggedElement
		v, err := r.Read()
		if err != nil {
			return nil, err
		}
		if t, ok := v.(CBORTag); ok {
			res.Tag = t
			iv, err := r.Read()
			if err != nil {
				return nil, err
			}
			res.Value = iv
		} else {
			res.Value = v
		}

		out[ks] = res
	}

	return out, nil
}

func (r *CBORReader) UntagIntMap(in map[int]TaggedElement) map[int]interface{} {
	out := make(map[int]interface{})
	for k, v := range in {
		if imap, ok := v.Value.(map[int]TaggedElement); ok {
			out[k] = r.UntagIntMap(imap)
		} else if smap, ok := v.Value.(map[string]TaggedElement); ok {
			out[k] = r.UntagStringMap(smap)
		} else if arr, ok := v.Value.([]TaggedElement); ok {
			out[k] = r.UntagArray(arr)
		} else {
			out[k] = v.Value
		}
	}
	return out
}

// UntagStringMap takes a map which contains optionally tagged elements and
// removes the tags from the map and any nested maps recursively. Also supports
// nested arrays.
func (r *CBORReader) UntagStringMap(in map[string]TaggedElement) map[string]interface{} {
	out := make(map[string]interface{})
	for k, v := range in {
		if smap, ok := v.Value.(map[string]TaggedElement); ok {
			out[k] = r.UntagStringMap(smap)
		} else if imap, ok := v.Value.(map[int]TaggedElement); ok {
			out[k] = r.UntagIntMap(imap)
		} else if iarr, ok := v.Value.([]TaggedElement); ok {
			out[k] = r.UntagArray(iarr)
		} else {
			out[k] = v.Value
		}
	}
	return out
}

// UntagArray takes an array containing optionally tagged elements and removes those
// tags recursively. Also supports nested maps.
func (r *CBORReader) UntagArray(in []TaggedElement) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		if iarr, ok := v.Value.([]TaggedElement); ok {
			out[i] = r.UntagArray(iarr)
		} else if smap, ok := v.Value.(map[string]TaggedElement); ok {
			out[i] = r.UntagStringMap(smap)
		} else if imap, ok := v.Value.(map[int]TaggedElement); ok {
			out[i] = r.UntagIntMap(imap)
		} else {
			out[i] = v.Value
		}
	}
	return out
}

func (r *CBORReader) ReadIntMapUntagged() (map[int]interface{}, error) {
	m, err := r.ReadIntMap()
	if err != nil {
		return nil, err
	}
	return r.UntagIntMap(m), nil
}

// ReadIntMap reads an integer keyed map.
func (r *CBORReader) ReadIntMap() (map[int]TaggedElement, error) {
	// read length
	u, _, _, err := r.readBasicUnsigned(majorMap)
	if err != nil {
		return nil, err
	}

	maplen := int(u)

	// create an output value
	out := make(map[int]TaggedElement)

	// now read as many key/value pairs as there should be
	for i := 0; i < maplen; i++ {
		k, err := r.ReadInt()
		if err != nil {
			return nil, err
		}

		var res TaggedElement

		v, err := r.Read()
		if err != nil {
			return nil, err
		}

		if t, ok := v.(CBORTag); ok {
			inner, err := r.Read()
			if err != nil {
				return nil, err
			}
			res.Tag = t
			res.Value = inner
		} else {
			res.Value = v
		}

		out[k] = res
	}

	return out, nil
}

// ReadTime reads a timestamp.
func (r *CBORReader) ReadTime() (time.Time, error) {
	// Case 1: the time is just a float, integer, or string.
	// In this case we just treat it as if it were tagged.
	ct, err := r.readType()
	if err != nil {
		return time.Unix(0, 0), err
	}
	switch ct & majorMask {
	case majorOther:
		if ct == majorOther|25 || ct == majorOther|26 || ct == majorOther|27 {
			// Floating point timestamp.
			r.pushbackType(ct)
			f, err := r.ReadFloat()
			if err != nil {
				return time.Unix(0, 0), err
			}
			whole, frac := math.Modf(f)
			secs := int64(whole)
			ns := int64(frac * 10e9)
			return time.Unix(secs, ns), nil
		}
		return time.Unix(0, 0), fmt.Errorf("got malformed majorOther type for timestamp: %x", ct)
	case majorNegative:
		fallthrough
	case majorUnsigned:
		r.pushbackType(ct)
		i, err := r.ReadInt()
		if err != nil {
			return time.Unix(0, 0), err
		}
		return time.Unix(int64(i), 0), nil
	case majorString:
		r.pushbackType(ct)
		s, err := r.ReadString()
		if err != nil {
			return time.Unix(0, 0), err
		}
		if t, err := time.Parse(time.RFC3339, s); err != nil {
			return time.Unix(0, 0), err
		} else {
			return t, nil
		}
	case majorTag:
		break // Fall through to the tag logic below.
	default:
		return time.Unix(0, 0), fmt.Errorf("unsupported tag for parsing time: %v", ct&majorMask)
	}
	tag, err := r.ReadTag()
	if err != nil {
		return time.Unix(0, 0), err
	}
	// Two tags are allowed: 0 for RFC3339 time, 1 for POSIX epoch time.
	switch tag {
	case TagDateTimeString:
		s, err := r.ReadString()
		if err != nil {
			return time.Unix(0, 0), err
		}
		if t, err := time.Parse(time.RFC3339, s); err != nil {
			return time.Unix(0, 0), err
		} else {
			return t, nil
		}
	case TagDateTimeEpoch:
		// This representation is in POSIX timestamp format in either positive
		// or negative integer, or floating point number.
		ct, err := r.readType()
		if err != nil {
			return time.Unix(0, 0), err
		}
		switch ct & majorMask {
		case majorNegative:
			fallthrough
		case majorUnsigned:
			r.pushbackType(ct)
			if i, err := r.ReadInt(); err != nil {
				return time.Unix(0, 0), err
			} else {
				return time.Unix(int64(i), 0), nil
			}
		case majorOther:
			if ct == majorOther|25 || ct == majorOther|26 || ct == majorOther|27 {
				r.pushbackType(ct)
				f, err := r.ReadFloat()
				if err != nil {
					return time.Unix(0, 0), err
				}
				whole, frac := math.Modf(f)
				secs := int64(whole)
				ns := int64(frac * 10e9)
				return time.Unix(secs, ns), nil
			} else {
				return time.Unix(0, 0), fmt.Errorf("got malformed majorOther type for timestamp: %x", ct)
			}
		default:
			return time.Unix(0, 0), fmt.Errorf("timestamp not understood")
		}
	default:
		return time.Unix(0, 0), fmt.Errorf("unrecognized time tag")
	}
}

// Read reads the next value as an arbitrary object from the CBOR reader. It
// returns a single interface{} of one of the following types, depending on the
// major type of the next CBOR object in the stream:
//
// - Unsigned (major 0): uint
// - Negative (major 1): int
// - Byte array (major 2): []byte
// - String (major 3): string
// - Array (major 4): []interface{}
// - Map (major 5): map[string]interface{}, with keys coerced to strings via Sprintf("%v").
// - Tag (major 6): CBORTag type
// - Other (major 7) float: float64
// - Other (major 7) true or false: bool
// - Other (major 7) nil: nil
// - anything else: currently an error

func (r *CBORReader) Read() (interface{}, error) {
	ct, err := r.readType()
	if err != nil {
		return nil, err
	}

	switch ct & majorSelect {
	case majorUnsigned, majorNegative:
		r.pushbackType(ct)
		return r.ReadInt()
	case majorBytes:
		r.pushbackType(ct)
		return r.ReadBytes()
	case majorString:
		r.pushbackType(ct)
		return r.ReadString()
	case majorArray:
		r.pushbackType(ct)
		return r.ReadArray()
	case majorMap:
		// When we are reading a map it can either be a int map or a string map.
		// To know which variant we are dealing with, we sample the first key
		// and use that to decide which variant parser to call.
		it, err := r.readType()
		if err != nil {
			return nil, err
		}
		r.pushbackType(ct)
		r.pushbackType(it)
		if it&majorSelect == majorUnsigned {
			return r.ReadIntMap()
		}
		return r.ReadStringMap()
	case majorTag:
		r.pushbackType(ct)
		return r.ReadTag()
	case majorOther:
		switch {
		case ct == majorOther|25 || ct == majorOther|26 || ct == majorOther|27:
			r.pushbackType(ct)
			return r.ReadFloat()
		case ct == 0xf4:
			return false, nil
		case ct == 0xf5:
			return true, nil
		case ct == 0xf6:
			return nil, nil
		}
	}

	// if we're here, pretend this isn't CBOR
	return nil, InvalidCBORError
}

// Unmarshal attempts to read the next value from the CBOR reader and store it
// in the value pointed to by v, according to v's type. Returns
// CBORTypeReadError if the type does not match or cannot be made to match.
// Values are handled as in Marshal().
func (r *CBORReader) Unmarshal(x interface{}) error {
	pv := reflect.ValueOf(x)

	// make sure we have a pointer to a thing
	if pv.Kind() != reflect.Ptr || pv.IsNil() {
		return fmt.Errorf("cannot unmarshal CBOR to non-pointer type %v", pv.Type())
	}

	// if the type implements unmarshaler, just do that.
	if m, ok := x.(CBORUnmarshaler); ok {
		return m.UnmarshalCBOR(r)
	}

	// make sure the thing is settable
	if !pv.Elem().CanSet() {
		return fmt.Errorf("cannot unmarshal CBOR to type %v: not settable by reflection", pv.Type())
	}

	// otherwise, read value based on value's element kind
	switch pv.Elem().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := r.ReadInt()
		if err != nil {
			return err
		}
		pv.Elem().SetInt(int64(i))
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		i, err := r.ReadInt()
		if err != nil {
			return err
		}
		pv.Elem().SetUint(uint64(i))
		return nil
	case reflect.String:
		s, err := r.ReadString()
		if err != nil {
			return err
		}
		pv.Elem().SetString(s)
		return nil
	case reflect.Slice:
		switch pv.Elem().Type() {
		case reflect.TypeOf([]string{}):
			sl, err := r.ReadStringArray()
			if err != nil {
				return err
			}
			pv.Elem().Set(reflect.ValueOf(sl))
			return nil
		case reflect.TypeOf([]int{}):
			sl, err := r.ReadIntArray()
			if err != nil {
				return err
			}
			pv.Elem().Set(reflect.ValueOf(sl))
			return nil
		default:
			sl, err := r.ReadArray()
			if err != nil {
				return err
			}
			pv.Elem().Set(reflect.ValueOf(sl))
			return nil
		}
	case reflect.Array:
		return fmt.Errorf("cannot unmarshal objects of type %v from CBOR", pv.Type().Elem())
	case reflect.Struct:
		// treat times sepcially
		if pv.Elem().Type() == reflect.TypeOf(time.Time{}) {
			t, err := r.ReadTime()
			if err != nil {
				return err
			}
			pv.Elem().Set(reflect.ValueOf(t))
			return nil
		}
		return r.readReflectedStruct(pv.Elem())
	case reflect.Bool:
		b, err := r.Read()
		if err != nil {
			return err
		}
		switch b.(type) {
		case bool:
			pv.Elem().Set(reflect.ValueOf(b))
		}
	case reflect.Interface:
		b, err := r.ReadTag()
		if err != nil {
			return err
		}
		t, ok := r.regTags[b]
		if !ok {
			return fmt.Errorf("CBOR tag %d was not registered on this reader", t)
		}
		// Check if we can assign the type to the interface x. N.B. x is a pointer so use elem.
		if dt := reflect.TypeOf(x).Elem(); !t.AssignableTo(dt) {
			return fmt.Errorf("registered type %v is not assignable to %v", t, dt)
		}
		// Instantiate t and call unmarshal on it.
		tins := reflect.New(t)
		// Set x to the instantiation of t.
		if err := r.Unmarshal(tins.Interface()); err != nil {
			return fmt.Errorf("failed to unmarshal interface inner type %v: %v", tins.Type().Name(), err)
		}
		pv.Elem().Set(tins)
		return nil
	}

	return fmt.Errorf("cannot unmarshal objects of type %v from CBOR", pv.Type().Elem())
}

// readReflectedStruct attempts to deserialize a map from the reader that
// matches the elements of a struct.
func (r *CBORReader) readReflectedStruct(pv reflect.Value) error {
	if pv.Kind() != reflect.Struct {
		return fmt.Errorf("readReflectedStruct wants only structs, got: %v", pv.Kind())
	}
	scs := structCBORSpec{}
	if err := scs.learnStruct(pv.Type()); err != nil {
		return fmt.Errorf("failed to learnStruct: %v", err)
	}

	// Either read a string map or an int map or a tag.
	ct, err := r.readType()
	if err != nil {
		return fmt.Errorf("failed to read tag: %v", err)
	}

	var m map[string]TaggedElement
	switch ct & majorSelect {
	case majorMap:
		// Read the right kind of map depending on what the struct supports.
		// TODO: support reading int maps.
		r.pushbackType(ct)
		m, err = r.ReadStringMap()
		if err != nil {
			return fmt.Errorf("failed to read string map for struct: %v", err)
		}
	case majorTag:
		return errors.New("tagged structs are not supported yet")
	}
	return scs.convertStringMapToStruct(m, pv, r.regTags)
}

type CBORUnmarshaler interface {
	UnmarshalCBOR(r *CBORReader) error
}
