package borat

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// structCBORSpec represents metadata for writing structures.
type structCBORSpec struct {
	tag            uint
	hasTag         bool
	intKeyForField map[string]int
	strKeyForField map[string]string
}

// TaggedElement is used to wrap elements which may be tagged for writing.
type TaggedElement struct {
	Tag   CBORTag
	Value interface{}
}

func (scs *structCBORSpec) usingIntKeys() bool {
	return scs.intKeyForField != nil
}

func (scs *structCBORSpec) learnStruct(t reflect.Type) error {
	for i, n := 0, t.NumField(); i < n; i++ {
		f := t.Field(i)

		// only process fields that are exportable
		if f.PkgPath == "" {
			// check for a struct tag
			tag := f.Tag.Get("cbor")
			if tag != "" {
				// generate map key from tag
				if strings.HasPrefix(tag, "#") {
					// Integer tag; parse it
					intKey, err := strconv.Atoi(tag[1:len(tag)])
					if err != nil {
						return fmt.Errorf("invalid integer key tag for %s.%s", t.Name(), f.Name)
					}
					if scs.strKeyForField != nil {
						return fmt.Errorf("cannot mix integer and string keys in %s", t.Name())
					}
					if scs.intKeyForField == nil {
						scs.intKeyForField = make(map[string]int)
					}
					scs.intKeyForField[f.Name] = intKey
				} else {
					if scs.intKeyForField != nil {
						return fmt.Errorf("cannot mix integer and string keys in %s", t.Name())
					}
					if scs.strKeyForField == nil {
						scs.strKeyForField = make(map[string]string)
					}
					scs.strKeyForField[f.Name] = tag
				}
			} else {
				// generate map key from name
				if scs.intKeyForField != nil {
					return fmt.Errorf("cannot mix integer and string keys in %s", t.Name())
				}
				if scs.strKeyForField == nil {
					scs.strKeyForField = make(map[string]string)
				}
				scs.strKeyForField[f.Name] = f.Name
			}
		} else if f.Name == "cborTag" {
			// structure indicates it would like to be tagged
			tag := f.Tag.Get("cbor")
			if tag != "" {
				// parse tag value as a base-10 int
				ct, err := strconv.Atoi(tag)
				if err != nil || ct < 0 {
					return fmt.Errorf("cannot parse special struct member cborTag %s in %s", tag, t.Name())
				}
				scs.tag = uint(ct)
				scs.hasTag = true
			}
		}
	}
	return nil
}

func (scs *structCBORSpec) convertStructToIntMap(v reflect.Value) (map[int]interface{}, error) {
	if scs.intKeyForField == nil {
		return nil, fmt.Errorf("can't convert %s to integer-keyed map", v.Type().Name())
	}

	out := make(map[int]interface{})

	for i, n := 0, v.NumField(); i < n; i++ {
		fieldName := v.Type().Field(i).Name
		fieldVal := v.Field(i)
		out[scs.intKeyForField[fieldName]] = fieldVal.Interface()
	}

	return out, nil
}

func (scs *structCBORSpec) convertIntMapToStruct(in map[int]interface{}, out reflect.Value) error {
	if scs.intKeyForField == nil {
		return fmt.Errorf("can't parse int map for struct type %s", out.Type().Name())
	}

	for i, n := 0, out.NumField(); i < n; i++ {
		fieldName := out.Type().Field(i).Name
		mapIdx := scs.intKeyForField[fieldName]
		// If this is a struct we should do something special here.
		if value, ok := in[mapIdx]; ok {
			// If this field is of type int but we have a uint64, we can cast
			// it, provided that it fits.
			if out.Field(i).Kind() == reflect.Int && reflect.ValueOf(value).Kind() == reflect.Uint64 {
				value = int(value.(uint64))
			}
			out.Field(i).Set(reflect.ValueOf(value))
		}
	}
	return nil
}

func (scs *structCBORSpec) convertStructToStringMap(v reflect.Value) (map[string]TaggedElement, error) {
	if scs.strKeyForField == nil {
		return nil, fmt.Errorf("can't convert %s to string-keyed map", v.Type().Name())
	}

	out := make(map[string]TaggedElement)

	for i, n := 0, v.NumField(); i < n; i++ {
		fieldName := v.Type().Field(i).Name
		if v.Type().Field(i).PkgPath != "" {
			continue
		}
		fieldVal := v.Field(i)
		// If it is a zero field, then do not include it in the map.
		// We do it this way to also catch if it is a nil pointer,
		// since the pointer kind is not invalid but it's inner value is.
		if reflect.ValueOf(fieldVal.Interface()).Kind() == reflect.Invalid {
			continue
		}
		// Do not tag structs over here because Marshal does that.
		elem := TaggedElement{
			Value: fieldVal.Interface(),
		}
		out[scs.strKeyForField[fieldName]] = elem
	}

	return out, nil
}

// handleSlice sets the field referenced by out to the data in in,
// out should be a slice of some type and in should also be a []interface{}
func (scs *structCBORSpec) handleSlice(out reflect.Value, in []TaggedElement, registry map[CBORTag]reflect.Type) error {
	if out.Kind() != reflect.Slice {
		return fmt.Errorf("called handleSlice on non-slice type %v: %v", out.Type().Name(), in)
	}
	k := out.Type().Elem().Kind()
	t := out.Type().Elem()
	if k == reflect.Ptr {
		k = out.Type().Elem().Elem().Kind()
		t = out.Type().Elem().Elem()
	}
	switch k {
	case reflect.Uint64, reflect.String:
		for i, e := range in {
			val := reflect.ValueOf(e.Value)
			if e.Tag != CBORTag(0) {
				t, ok := registry[e.Tag]
				if !ok {
					return fmt.Errorf("unknown tag %d", e.Tag)
				}
				if !val.Type().ConvertibleTo(t) {
					return fmt.Errorf("%v not convertible to tag type %v", val.Type(), t)
				}
				out.Index(i).Set(val.Convert(t))
			} else {
				out.Index(i).Set(reflect.ValueOf(e.Value))
			}
		}
	case reflect.Int:
		it := reflect.TypeOf(int(0))
		for i, e := range in {
			val := reflect.ValueOf(e.Value)
			if e.Tag != CBORTag(0) {
				t, ok := registry[e.Tag]
				if !ok {
					return fmt.Errorf("unknown tag %d", e.Tag)
				}
				if !val.Type().ConvertibleTo(t) {
					return fmt.Errorf("%v not convertible to tag type %v", val.Type(), t)
				}
				it = t
			}
			out.Index(i).Set(val.Convert(it))
		}
	case reflect.Uint8:
		u8t := reflect.TypeOf(uint8(0))
		for i, e := range in {
			val := reflect.ValueOf(e.Value)
			if e.Tag != CBORTag(0) {
				t, ok := registry[e.Tag]
				if !ok {
					return fmt.Errorf("unknown tag %d", e.Tag)
				}
				if !val.Type().ConvertibleTo(t) {
					return fmt.Errorf("%v not convertible to tag type %v", val.Type(), t)
				}
				u8t = t
			}
			out.Index(i).Set(val.Convert(u8t))
		}
	case reflect.Struct:
		childScs := &structCBORSpec{}
		childScs.learnStruct(t)
		for i, e := range in {
			childScs.convertStringMapToStruct(e.Value.(map[string]TaggedElement), out.Index(i), registry)
		}
	case reflect.Slice:
		for i, inElem := range in {
			slen := len(inElem.Value.([]TaggedElement))
			slice := reflect.MakeSlice(out.Type().Elem(), slen, slen)
			out.Index(i).Set(slice)
			scs.handleSlice(out.Index(i), inElem.Value.([]TaggedElement), registry)
		}
	case reflect.Interface:
		for i, inElem := range in {
			te, ok := inElem.Value.(map[string]TaggedElement)
			if !ok {
				return fmt.Errorf("idx %d: expected in parameter to be array of maps but got: %T: %v", i, inElem, inElem)
			}
			st, ok := registry[inElem.Tag]
			if !ok {
				return fmt.Errorf("tag %v not found in registry, value: %v", inElem.Tag, inElem.Value)
			}
			inst := reflect.New(st)
			childScs := structCBORSpec{}
			if err := childScs.learnStruct(st); err != nil {
				return err
			}
			if err := childScs.convertStringMapToStruct(te, inst.Elem(), registry); err != nil {
				return err
			}
			out.Index(i).Set(inst)
		}
	default:
		return fmt.Errorf("unsupported slice type: %v", k)
	}
	return nil
}

func (scs *structCBORSpec) handleArray(out reflect.Value, in TaggedElement) error {
	if out.Kind() != reflect.Array {
		return fmt.Errorf("called handleArray on non-array type: %v", out.Kind())
	}
	switch out.Type().Elem().Kind() {
	case reflect.Uint64, reflect.String:
		for i, e := range in.Value.([]TaggedElement) {
			out.Index(i).Set(reflect.ValueOf(e.Value))
		}
	case reflect.Uint32:
		for i, e := range in.Value.([]TaggedElement) {
			dc := uint32(e.Value.(int))
			out.Index(i).Set(reflect.ValueOf(dc))
		}
	case reflect.Uint16:
		for i, e := range in.Value.([]TaggedElement) {
			dc := uint16(e.Value.(int))
			out.Index(i).Set(reflect.ValueOf(dc))
		}
	case reflect.Uint8:
		for i, e := range in.Value.([]TaggedElement) {
			dc := uint8(e.Value.(int))
			out.Index(i).Set(reflect.ValueOf(dc))
		}
	case reflect.Struct:
		return fmt.Errorf("handleArray not yet implemented for type %T: %v", in.Value, in.Value)
	}
	return nil
}

// out must be a value of type struct. If the current thing is an interface then it should be
// resolved to the actual type by the caller.
func (scs *structCBORSpec) convertStringMapToStruct(in map[string]TaggedElement, out reflect.Value, registry map[CBORTag]reflect.Type) error {
	if scs.strKeyForField == nil {
		return fmt.Errorf("cant parse string map for struct type %s", out.Type().Name())
	}
	// Allocate the pointer if we were actually given a pointer to a struct.
	// Then we set out to the indirect of that pointer to reuse our exisitng logic.
	if out.Kind() == reflect.Ptr {
		out.Set(reflect.New(out.Type().Elem()))
		out = reflect.Indirect(out)
	}
	if out.Kind() != reflect.Struct {
		return fmt.Errorf("cannot convertStringMapToStruct on non-struct: %v", out.Kind())
	}
	for i, n := 0, out.NumField(); i < n; i++ {
		fieldName := out.Type().Field(i).Name
		mapIdx := scs.strKeyForField[fieldName]
		// If this is a struct we should do something special here.
		if elem, ok := in[mapIdx]; ok {
			// If this field is of type int but we have a uint64, we can cast
			// it, provided that it fits.
			if out.Field(i).Kind() == reflect.Int && reflect.ValueOf(elem.Value).Kind() == reflect.Uint64 {
				elem.Value = int(elem.Value.(uint64))
			}
			if out.Field(i).Kind() == reflect.Slice {
				// We need to make a slice with the correct length and type.
				slen := len(elem.Value.([]TaggedElement))
				slice := reflect.MakeSlice(out.Field(i).Type(), slen, slen)
				out.Field(i).Set(slice)
				if err := scs.handleSlice(out.Field(i), elem.Value.([]TaggedElement), registry); err != nil {
					return fmt.Errorf("convertStringMapToStruct failed to call handleSlice: %v", err)
				}
			} else if out.Field(i).Kind() == reflect.Array {
				innerType := out.Field(i).Type().Elem()
				arr := reflect.New(reflect.ArrayOf(len(elem.Value.([]TaggedElement)), innerType)).Elem()
				out.Field(i).Set(arr)
				if err := scs.handleArray(out.Field(i), elem); err != nil {
					return fmt.Errorf("convertStringMapToStruct failed to call handleArray: %v", err)
				}
			} else if out.Field(i).Kind() == reflect.Struct {
				childScs := structCBORSpec{}
				childScs.learnStruct(out.Field(i).Type())
				if err := childScs.convertStringMapToStruct(elem.Value.(map[string]TaggedElement), out.Field(i), registry); err != nil {
					return fmt.Errorf("failed to convert map to struct for type %s: %v", out.Type().Name(), err)
				}
			} else if out.Field(i).Kind() == reflect.Interface {
				concrete, ok := registry[elem.Tag]
				if !ok {
					return fmt.Errorf("field: %s, unsupported tag %d, type %v", fieldName, elem.Tag, out.Type().Name())
				}
				inst := reflect.New(concrete)
				if concrete.Kind() == reflect.Struct {
					childScs := structCBORSpec{}
					if err := childScs.learnStruct(concrete); err != nil {
						return fmt.Errorf("failed to learn struct: %v", err)
					}
					if err := childScs.convertStringMapToStruct(elem.Value.(map[string]TaggedElement), inst.Elem(), registry); err != nil {
						return err
					}
				} else if concrete.Kind() == reflect.Slice {
					// If the type is directly assignable then just assign it.
					val := reflect.ValueOf(elem.Value)
					if inst.Kind() == reflect.Ptr && val.Kind() != reflect.Ptr {
						inst = inst.Elem()
					}
					if val.Type().AssignableTo(inst.Type()) {
						inst.Set(val)
					} else if val.Type().ConvertibleTo(inst.Type()) {
						conv := val.Convert(inst.Type())
						inst.Set(conv)
					} else {
						iter, ok := elem.Value.([]TaggedElement)
						if !ok {
							return fmt.Errorf("recieved type was not a slice, it was a %T", elem.Value)
						}
						inst = reflect.MakeSlice(concrete, len(iter), len(iter))
						if err := scs.handleSlice(inst, iter, registry); err != nil {
							return fmt.Errorf("failed to handleSlice: %v", err)
						}
					}
				} else {
					val := reflect.ValueOf(elem.Value)
					if inst.Kind() == reflect.Ptr && val.Kind() != reflect.Ptr {
						inst = inst.Elem()
					}
					// Check assignability
					inType := val.Type()
					outType := inst.Type()
					if inType.AssignableTo(outType) {
						inst.Set(val)
					} else if inType.ConvertibleTo(outType) {
						converted := val.Convert(outType)
						inst.Set(converted)
					} else {
						return fmt.Errorf("could not assign %v to %v", inType, outType)
					}
				}
				if inst.Kind() == reflect.Ptr {
					inst = inst.Elem()
				}
				out.Field(i).Set(inst)
			} else {
				val := reflect.ValueOf(elem.Value)
				// Check assignability
				inType := val.Type()
				outType := out.Field(i).Type()
				if inType.AssignableTo(outType) {
					out.Field(i).Set(val)
				} else if inType.ConvertibleTo(outType) {
					converted := val.Convert(outType)
					out.Field(i).Set(converted)
				} else {
					return fmt.Errorf("could not assign %v to %v", inType, outType)
				}
			}
		} else {
			// Do nothing if this field does was not specified in the map.
		}
	}
	return nil
}
