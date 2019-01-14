package object

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"golang.org/x/crypto/ed25519"
)

//Object contains a Value of to the specified Type
type Object struct {
	Type  Type
	Value interface{}
}

// UnmarshalArray takes in a CBOR decoded array and populates the object.
func (obj *Object) UnmarshalArray(in []interface{}) error {
	switch Type(in[0].(int)) {
	case OTName:
		no := Name{Types: make([]Type, 0)}
		no.Name = in[1].(string)
		for _, ot := range in[2].([]interface{}) {
			no.Types = append(no.Types, Type(ot.(int)))
		}
		obj.Value = no
	case OTIP6Addr:
		ip := net.IP(in[1].([]byte))
		obj.Value = ip.String()
	case OTIP4Addr:
		ip := net.IP(in[1].([]byte))
		obj.Value = ip.String()
	case OTRedirection:
		obj.Value = in[1]
	case OTDelegation:
		alg := in[1].(int)
		ks := keys.KeySpaceID(in[2].(int))
		kp := int(in[3].(int))
		vs := int64(in[4].(int))
		vu := int64(in[5].(int))
		var key interface{}
		switch algorithmTypes.Signature(alg) {
		case algorithmTypes.Ed25519:
			key = ed25519.PublicKey(in[6].([]byte))
		default:
			return fmt.Errorf("unsupported algorithm: %v", alg)
		}
		pkey := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: algorithmTypes.Signature(alg),
				KeySpace:  ks,
				KeyPhase:  kp,
			},
			ValidSince: vs,
			ValidUntil: vu,
			Key:        key,
		}
		obj.Value = pkey
	case OTNameset:
		obj.Value = NamesetExpr(in[1].(string))
	case OTCertInfo:
		co := Certificate{
			Type:     ProtocolType(in[1].(int)),
			Usage:    CertificateUsage(in[2].(int)),
			HashAlgo: algorithmTypes.Hash(in[3].(int)),
			Data:     in[4].([]byte),
		}
		obj.Value = co
	case OTServiceInfo:
		si := ServiceInfo{
			Name:     in[1].(string),
			Port:     uint16(in[2].(int)),
			Priority: uint(in[3].(int)),
		}
		obj.Value = si
	case OTRegistrar:
		obj.Value = in[2].(string)
	case OTRegistrant:
		obj.Value = in[2].(string)
	case OTInfraKey:
		alg := in[1]
		ks := in[2].(keys.KeySpaceID)
		kp := in[3].(int)
		vs := in[4].(int64)
		vu := in[5].(int64)
		var key interface{}
		switch alg.(algorithmTypes.Signature) {
		case algorithmTypes.Ed25519:
			key = ed25519.PublicKey(in[6].([]byte))
		default:
			return fmt.Errorf("unsupported algorithm: %v", alg)
		}
		pkey := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: alg.(algorithmTypes.Signature),
				KeySpace:  ks,
				KeyPhase:  kp,
			},
			ValidSince: vs,
			ValidUntil: vu,
			Key:        key,
		}
		obj.Value = pkey
	case OTExtraKey:
		alg := in[1].(algorithmTypes.Signature)
		ks := in[2].(keys.KeySpaceID)
		var key interface{}
		switch alg {
		case algorithmTypes.Ed25519:
			key = ed25519.PublicKey(in[3].([]byte))
		default:
			return fmt.Errorf("unsupported algorithm: %v", alg)
		}
		pk := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: alg,
				KeySpace:  ks,
			},
			Key: key,
		}
		obj.Value = pk
	case OTNextKey:
		// TODO: Implement OTNextKey.
		log.Error("not yet implemented")
	default:
		return errors.New("unknown object type in unmarshalling object")
	}
	obj.Type = Type(in[0].(int))
	return nil
}

// MarshalCBOR implements a CBORMarshaler.
func (obj Object) MarshalCBOR(w *cbor.CBORWriter) error {
	var res []interface{}
	switch obj.Type {
	case OTName:
		no, ok := obj.Value.(Name)
		if !ok {
			return fmt.Errorf("expected OTName to be Name but got: %T", obj.Value)
		}
		ots := make([]int, len(no.Types))
		for i, ot := range no.Types {
			ots[i] = int(ot)
		}
		res = []interface{}{OTName, no.Name, ots}
	case OTIP6Addr:
		addrStr := obj.Value.(string)
		addr := net.ParseIP(addrStr)
		res = []interface{}{OTIP6Addr, []byte(addr)}
	case OTIP4Addr:
		addrStr := obj.Value.(string)
		addr := net.ParseIP(addrStr)
		res = []interface{}{OTIP4Addr, []byte(addr)}
	case OTRedirection:
		res = []interface{}{OTRedirection, obj.Value}
	case OTDelegation:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", obj.Value)
		}
		// TODO: ValidSince and ValidUntil should be tagged.
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTDelegation, int(pkey.Algorithm), int(pkey.KeySpace), pkey.KeyPhase, pkey.ValidSince, pkey.ValidUntil, b}
	case OTNameset:
		nse, ok := obj.Value.(NamesetExpr)
		if !ok {
			return fmt.Errorf("expected OTNameset value to be NamesetExpr but got: %T", obj.Value)
		}
		res = []interface{}{OTNameset, string(nse)}
	case OTCertInfo:
		co, ok := obj.Value.(Certificate)
		if !ok {
			return fmt.Errorf("expected OTCertInfo object to be Certificate, but got: %T", obj.Value)
		}
		res = []interface{}{OTCertInfo, int(co.Type), int(co.Usage), int(co.HashAlgo), co.Data}
	case OTServiceInfo:
		si, ok := obj.Value.(ServiceInfo)
		if !ok {
			return fmt.Errorf("expected OTServiceInfo object to be ServiceInfo, but got: %T", obj.Value)
		}
		res = []interface{}{OTServiceInfo, si.Name, si.Port, si.Priority}
	case OTRegistrar:
		rstr, ok := obj.Value.(string)
		if !ok {
			return fmt.Errorf("expected OTRegistrar object to be string but got: %T", obj.Value)
		}
		res = []interface{}{OTRegistrar, rstr}
	case OTRegistrant:
		rstr, ok := obj.Value.(string)
		if !ok {
			return fmt.Errorf("expected OTRegistrant object to be string but got: %T", obj.Value)
		}
		res = []interface{}{OTRegistrant, rstr}
	case OTInfraKey:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", obj.Value)
		}
		// TODO: ValidSince and ValidUntl should be tagged.
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTInfraKey, int(pkey.Algorithm), int(pkey.KeySpace), pkey.KeyPhase, pkey.ValidSince, pkey.ValidUntil, b}
	case OTExtraKey:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", obj.Value)
		}
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTExtraKey, int(pkey.Algorithm), int(pkey.KeySpace), b}
	case OTNextKey:
	default:
		return fmt.Errorf("unknown object type: %v", obj.Type)
	}
	return w.WriteArray(res)
}

func pubkeyToCBORBytes(p keys.PublicKey) []byte {
	switch p.Algorithm {
	case algorithmTypes.Ed25519:
		return []byte(p.Key.(ed25519.PublicKey))
	case algorithmTypes.Ed448:
		panic("Unsupported algorithm.")
	default:
		panic("Unsupported algorithm.")
	}
}

//Sort sorts the content of o lexicographically.
func (o *Object) Sort() {
	if name, ok := o.Value.(Name); ok {
		sort.Slice(name.Types, func(i, j int) bool { return name.Types[i] < name.Types[j] })
	}
	if o.Type == OTExtraKey {
		log.Error("Sort not implemented for external key. Format not yet defined")
	}
}

//CompareTo compares two objects and returns 0 if they are equal, 1 if o is greater than object and -1 if o is smaller than object
func (o Object) CompareTo(object Object) int {
	if o.Type < object.Type {
		return -1
	} else if o.Type > object.Type {
		return 1
	}
	switch v1 := o.Value.(type) {
	case Name:
		if v2, ok := object.Value.(Name); ok {
			return v1.CompareTo(v2)
		}
		logObjectTypeAssertionFailure(object.Type, object.Value)
	case string:
		if v2, ok := object.Value.(string); ok {
			if v1 < v2 {
				return -1
			} else if v1 > v2 {
				return 1
			}
		} else {
			logObjectTypeAssertionFailure(object.Type, object.Value)
		}
	case keys.PublicKey:
		if v2, ok := object.Value.(keys.PublicKey); ok {
			return v1.CompareTo(v2)
		}
		logObjectTypeAssertionFailure(object.Type, object.Value)
	case NamesetExpr:
		if v2, ok := object.Value.(NamesetExpr); ok {
			if v1 < v2 {
				return -1
			} else if v1 > v2 {
				return 1
			}
		} else {
			logObjectTypeAssertionFailure(object.Type, object.Value)
		}
	case Certificate:
		if v2, ok := object.Value.(Certificate); ok {
			return v1.CompareTo(v2)
		}
		logObjectTypeAssertionFailure(object.Type, object.Value)
	case ServiceInfo:
		if v2, ok := object.Value.(ServiceInfo); ok {
			return v1.CompareTo(v2)
		}
		logObjectTypeAssertionFailure(object.Type, object.Value)
	default:
		log.Warn("Unsupported Value type", "type", fmt.Sprintf("%T", o.Value))
	}
	return 0
}

//String implements Stringer interface
func (o Object) String() string {
	return fmt.Sprintf("OT:%d OV:%v", o.Type, o.Value)
}

//logObjectTypeAssertionFailure logs that it was not possible to type assert value as t
func logObjectTypeAssertionFailure(t Type, value interface{}) {
	log.Error("Object Type and corresponding type assertion of object's value do not match",
		"objectType", t, "objectValueType", fmt.Sprintf("%T", value))
}

//Type identifier for object connection. ID chosen according to RAINS Protocol Specification
type Type int

//String returns the ID as a string
func (o Type) String() string {
	return strconv.Itoa(int(o))
}

const (
	OTName        Type = 1
	OTIP6Addr     Type = 2
	OTIP4Addr     Type = 3
	OTRedirection Type = 4
	OTDelegation  Type = 5
	OTNameset     Type = 6
	OTCertInfo    Type = 7
	OTServiceInfo Type = 8
	OTRegistrar   Type = 9
	OTRegistrant  Type = 10
	OTInfraKey    Type = 11
	OTExtraKey    Type = 12
	OTNextKey     Type = 13
)

//Name contains a name associated with a name as an alias. Types specifies for which object connection the alias is valid
type Name struct {
	Name string
	//Types for which the Name is valid
	Types []Type
}

//CompareTo compares two nameObjects and returns 0 if they are equal, 1 if n is greater than nameObject and -1 if n is smaller than nameObject
func (n Name) CompareTo(nameObj Name) int {
	if n.Name < nameObj.Name {
		return -1
	} else if n.Name > nameObj.Name {
		return 1
	} else if len(n.Types) < len(nameObj.Types) {
		return -1
	} else if len(n.Types) > len(nameObj.Types) {
		return 1
	}
	for i, t := range n.Types {
		if t < nameObj.Types[i] {
			return -1
		} else if t > nameObj.Types[i] {
			return 1
		}
	}
	return 0
}

//NamesetExpr encodes a modified POSIX Extended Regular Expression format
type NamesetExpr string

//Certificate contains a certificate and its meta data (type, usage and hash algorithm identifier)
type Certificate struct {
	Type     ProtocolType
	Usage    CertificateUsage
	HashAlgo algorithmTypes.Hash
	Data     []byte
}

//CompareTo compares two certificateObject objects and returns 0 if they are equal, 1 if c is greater than cert and -1 if c is smaller than cert
func (c Certificate) CompareTo(cert Certificate) int {
	if c.Type < cert.Type {
		return -1
	} else if c.Type > cert.Type {
		return 1
	} else if c.Usage < cert.Usage {
		return -1
	} else if c.Usage > cert.Usage {
		return 1
	} else if c.HashAlgo < cert.HashAlgo {
		return -1
	} else if c.HashAlgo > cert.HashAlgo {
		return 1
	}
	return bytes.Compare(c.Data, cert.Data)
}

//String implements Stringer interface
func (c Certificate) String() string {
	return fmt.Sprintf("{%d %d %d %s}", c.Type, c.Usage, c.HashAlgo, hex.EncodeToString(c.Data))
}

//ProtocolType is an identifier for a protocol. The ID is chosen according to the RAINS Protocol Specification.
type ProtocolType int

const (
	PTUnspecified ProtocolType = 0
	PTTLS         ProtocolType = 1
)

//CertificateUsage is an identifier for a certificate usage. The ID is chosen according to the RAINS Protocol Specification.
type CertificateUsage int

const (
	CUTrustAnchor CertificateUsage = 2
	CUEndEntity   CertificateUsage = 3
)

//ServiceInfo contains information how to access a named service
type ServiceInfo struct {
	Name     string
	Port     uint16
	Priority uint
}

//CompareTo compares two serviceInfo objects and returns 0 if they are equal, 1 if s is greater than serviceInfo and -1 if s is smaller than serviceInfo
func (s ServiceInfo) CompareTo(serviceInfo ServiceInfo) int {
	if s.Name < serviceInfo.Name {
		return -1
	} else if s.Name > serviceInfo.Name {
		return 1
	} else if s.Port < serviceInfo.Port {
		return -1
	} else if s.Port > serviceInfo.Port {
		return 1
	} else if s.Priority < serviceInfo.Priority {
		return -1
	} else if s.Priority > serviceInfo.Priority {
		return 1
	}
	return 0
}
