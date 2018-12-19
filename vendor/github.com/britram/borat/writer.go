package borat

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"time"
)

// DateTimePref indicates the format for marshaling timestamps.
type DateTimePref int

const (
	// DateTimePrefInt causes a timestamp to be encoded as an int.
	DateTimePrefInt = iota
	// DateTimePrefFloat causes a timestamp to be encoded as a float.
	DateTimePrefFloat
	// DateTimePrefString causes a timestamp to be encoded as a String.
	DateTimePrefString
)

// CBORWriter writes CBOR to an output stream. It provides a relatively
// low-level interface, allowing the caller to write typed data to the stream as
// CBOR, as well as a higher-level Marshal interface which uses reflection to
// properly encode arbitrary objects as CBOR.
type CBORWriter struct {
	dateTimePref DateTimePref
	out          io.Writer
	scsCache     map[reflect.Type]*structCBORSpec
	regTags      map[reflect.Type]CBORTag
}

// NewCBORWriter creates a new CBORWriter around a given output stream
// (io.Writer).
func NewCBORWriter(out io.Writer) *CBORWriter {
	w := &CBORWriter{
		dateTimePref: DateTimePrefInt,
		out:          out,
		scsCache:     make(map[reflect.Type]*structCBORSpec),
		regTags:      make(map[reflect.Type]CBORTag),
	}
	return w
}

// RegisterCBORTag adds a CBOR tag for annotating a serialized struct.
func (w *CBORWriter) RegisterCBORTag(tag CBORTag, inst interface{}) error {
	t := reflect.TypeOf(inst)
	if _, ok := w.regTags[t]; ok {
		return fmt.Errorf("tag %d is already registered", tag)
	}
	w.regTags[t] = tag
	return nil
}

func (w *CBORWriter) writeBasicInt(u uint64, mt byte) error {
	var out []byte

	if u < 24 {
		out = []byte{mt | byte(u)}
	} else if u < math.MaxUint8 {
		out = []byte{mt | 24, byte(u)}
	} else if u < math.MaxUint16 {
		out = []byte{mt | 25, 0, 0}
		binary.BigEndian.PutUint16(out[1:3], uint16(u))
	} else if u < math.MaxUint32 {
		out = []byte{mt | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[1:5], uint32(u))
	} else {
		out = []byte{mt | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(out[1:9], uint64(u))
	}

	_, err := w.out.Write(out)
	return err
}

// WriteTag writes a CBOR tag to the output stream. CBOR tags are used to note the semantics of the following object.
func (w *CBORWriter) WriteTag(t CBORTag) error {
	return w.writeBasicInt(uint64(t), majorTag)
}

// WriteInt writes an integer to the output stream.
func (w *CBORWriter) WriteInt(i int) error {
	var u uint64
	var mt byte
	if i >= 0 {
		u = uint64(i)
		mt = majorUnsigned
	} else {
		u = uint64(-1 - i)
		mt = majorNegative
	}

	return w.writeBasicInt(u, mt)
}

// WriteFloat writes a floating point number to the output stream.
func (w *CBORWriter) WriteFloat(f float64) error {
	out := []byte{majorOther | 27, 0, 0, 0, 0, 0, 0, 0, 0}
	u := math.Float64bits(f)
	binary.BigEndian.PutUint64(out[1:9], u)

	_, err := w.out.Write(out)
	return err
}

func (w *CBORWriter) writeBasicBytes(b []byte, mt byte) error {
	if err := w.writeBasicInt(uint64(len(b)), mt); err != nil {
		return err
	}

	_, err := w.out.Write(b)
	return err
}

// WriteBytes writes a byte array to the output stream.
func (w *CBORWriter) WriteBytes(b []byte) error {
	return w.writeBasicBytes(b, majorBytes)
}

// WriteString writes a string to the output stream.
func (w *CBORWriter) WriteString(s string) error {
	return w.writeBasicBytes([]byte(s), majorString)
}

// WriteBool writes a boolean value to the output stream.
func (w *CBORWriter) WriteBool(b bool) error {
	out := []byte{0xf4}
	if b {
		out[0] = 0xf5
	}

	_, err := w.out.Write(out)
	return err
}

// WriteTime writes a time value to the output stream.
func (w *CBORWriter) WriteTime(t time.Time) error {
	switch w.dateTimePref {
	case DateTimePrefInt:
		if err := w.WriteTag(TagDateTimeEpoch); err != nil {
			return err
		}
		return w.WriteInt(int(t.Unix()))
	case DateTimePrefFloat:
		return fmt.Errorf("Unsupported")
	case DateTimePrefString:
		return fmt.Errorf("Unsupported")
	default:
		panic("Unsupported date time preference format.")
	}
}

// WriteNil writes a nil to the output stream
func (w *CBORWriter) WriteNil() error {
	out := []byte{0xf6}
	_, err := w.out.Write(out)
	return err
}

// WriteArray writes an arbitrary slice to the output stream. Each of the
// elements of the array will be reflected and written as appropriate.
func (w *CBORWriter) WriteArray(a []interface{}) error {
	if err := w.writeBasicInt(uint64(len(a)), majorArray); err != nil {
		return err
	}

	for i := range a {
		if err := w.Marshal(a[i]); err != nil {
			return err
		}
	}

	return nil
}

// WriteStringArray writes a slice of strings to the output stream.
func (w *CBORWriter) WriteStringArray(a []string) error {
	if err := w.writeBasicInt(uint64(len(a)), majorArray); err != nil {
		return err
	}

	for i := range a {
		if err := w.WriteString(a[i]); err != nil {
			return err
		}
	}

	return nil
}

// WriteIntArray writes a slice of integers to the output stream.
func (w *CBORWriter) WriteIntArray(a []int) error {
	if err := w.writeBasicInt(uint64(len(a)), majorArray); err != nil {
		return err
	}

	for i := range a {
		if err := w.WriteInt(a[i]); err != nil {
			return err
		}
	}

	return nil
}

// WriteStringMap writes a map keyed by strings to arbitrary types to the output
// stream. Each of the values of the map will be reflected and written as
// appropriate.
func (w *CBORWriter) WriteStringMap(m map[string]interface{}) error {
	if err := w.writeBasicInt(uint64(len(m)), majorMap); err != nil {
		return err
	}

	// get sorted keys array
	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	sort.Strings(keys)

	// serialize based on ordered keys
	for _, k := range keys {
		if err := w.WriteString(k); err != nil {
			return err
		}
		if err := w.Marshal(m[k]); err != nil {
			return err
		}
	}

	return nil
}

// writeTaggedStringMap writes a map where keys are optionally tagged.
func (w *CBORWriter) writeTaggedStringMap(m map[string]TaggedElement) error {
	if err := w.writeBasicInt(uint64(len(m)), majorMap); err != nil {
		return err
	}

	// get sorted keys array
	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	sort.Strings(keys)

	// serialize based on ordered keys
	for _, k := range keys {
		if err := w.WriteString(k); err != nil {
			return err
		}
		if m[k].Tag != CBORTag(0) {
			if err := w.WriteTag(m[k].Tag); err != nil {
				return err
			}
		}
		if err := w.Marshal(m[k].Value); err != nil {
			return err
		}
	}
	return nil
}

// WriteIntMap writes a map keyed by integers to arbitrary types to the output
// stream. Each of the values of the map will be reflected and written as
// appropriate.
func (w *CBORWriter) WriteIntMap(m map[int]interface{}) error {
	if err := w.writeBasicInt(uint64(len(m)), majorMap); err != nil {
		return err
	}

	// get sorted keys array
	keys := make([]int, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	sort.Ints(keys)

	// serialize based on ordered keys
	for _, k := range keys {
		if err := w.WriteInt(k); err != nil {
			return err
		}
		if err := w.Marshal(m[k]); err != nil {
			return err
		}
	}

	return nil
}

// Marshal marshals an arbitrary object to the output stream using reflection.
// If the object is a primitive type, it will be marshaled as such. If it
// implements CBORMarshaler, its MarshalCBOR function will be called. If the
// object is a structure with CBOR struct tags, those struct tags will be used.
// If the object is a struct without CBOR struct tags, the struct will be
// marshaled as a map of strings to objects using the names of the public
// members of the struct.
func (w *CBORWriter) Marshal(x interface{}) error {

	v := reflect.ValueOf(x)

	// if the type implements marshaler, just do that
	if m, ok := x.(CBORMarshaler); ok {
		return m.MarshalCBOR(w)
	}

	if v.Kind() == reflect.Ptr {
		if inner := v.Elem(); inner.IsValid() {
			return w.Marshal(inner.Interface())
		}
		return fmt.Errorf("invalid pointer: %v", v)
	}

	if v.Kind() == reflect.Interface {
		panic(fmt.Sprintf("this is an interface: %v", v.Type().Name()))
	}

	// If this object is tagged in the registry then we should write a cbor tag first.
	// Only do this if the value is non zero.
	if x != nil && !reflect.DeepEqual(x, reflect.Zero(reflect.TypeOf(x)).Interface()) {
		t := v.Type()
		if tag, ok := w.regTags[t]; ok {
			if err := w.WriteTag(CBORTag(tag)); err != nil {
				return err
			}
		}
	}

	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return w.WriteInt(int(v.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return w.writeBasicInt(v.Uint(), majorUnsigned)
	case reflect.Bool:
		return w.WriteBool(v.Bool())
	case reflect.String:
		return w.WriteString(v.String())
	case reflect.Slice:
		// treat byte slices specially
		switch v.Type() {
		case reflect.TypeOf([]byte{}):
			return w.WriteBytes(v.Bytes())
		case reflect.TypeOf([]string{}):
			return w.WriteStringArray(v.Interface().([]string))
		case reflect.TypeOf([]int{}):
			return w.WriteIntArray(v.Interface().([]int))
		default:
			iftype := make([]interface{}, v.Len())
			for i := 0; i < v.Len(); i++ {
				iftype[i] = v.Index(i).Interface()
			}
			return w.WriteArray(iftype)
		}
	case reflect.Array:
		s := make([]interface{}, v.Len())
		for i := 0; i < v.Len(); i++ {
			s[i] = v.Index(i).Interface()
		}
		return w.WriteArray(s)
	case reflect.Struct:
		// treat times sepcially
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return w.WriteTime(v.Interface().(time.Time))
		}
		return w.writeReflectedStruct(v)
	case reflect.Invalid:
		return fmt.Errorf("Trying to marshal Invalid: %v", v)
	default:
		return fmt.Errorf("Cannot marshal objects of kind %v to CBOR", v.Kind())
	}
}

func (w *CBORWriter) writeReflectedStruct(v reflect.Value) error {
	// retrieve or cache structure specification
	var scs *structCBORSpec
	scs, ok := w.scsCache[v.Type()]
	if !ok {
		scs = new(structCBORSpec)
		scs.learnStruct(v.Type())
		w.scsCache[v.Type()] = scs
	}

	// and write either an int map or a string map
	if scs.usingIntKeys() {
		imap, err := scs.convertStructToIntMap(v)
		if err != nil {
			return fmt.Errorf("failed to convert struct to int map: %v", err)
		}
		return w.WriteIntMap(imap)
	}
	tsm, err := scs.convertStructToStringMap(v)
	if err != nil {
		return fmt.Errorf("failed to convert struct to string map: %v", err)
	}
	return w.writeTaggedStringMap(tsm)
}

// CBORMarshaler represents an object that can write itself to a CBORWriter
type CBORMarshaler interface {
	MarshalCBOR(w *CBORWriter) error
}
