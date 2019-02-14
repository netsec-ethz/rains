package object

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"

	cbor "github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/scionproto/scion/go/lib/snet"
	"golang.org/x/crypto/ed25519"
)

//Object contains a Value of to the specified Type
type Object struct {
	Type  Type
	Value interface{}
}

// UnmarshalArray takes in a CBOR decoded array and populates the object.
func (obj *Object) UnmarshalArray(in []interface{}) error {
	t, ok := in[0].(int)
	if !ok {
		return errors.New("cbor object encoding first element (type) must be an int")
	}
	switch Type(t) {
	case OTName:
		no := Name{Types: make([]Type, 0)}
		no.Name, ok = in[1].(string)
		if !ok {
			return errors.New("cbor object encoding of name not a string")
		}
		ots, ok := in[2].([]interface{})
		if !ok {
			return errors.New("cbor object encoding of name not an array")
		}
		for _, ot := range ots {
			o, ok := ot.(int)
			if !ok {
				return errors.New("cbor object encoding of name not an array")
			}
			no.Types = append(no.Types, Type(o))
		}
		obj.Value = no
	case OTIP6Addr:
		v, ok := in[1].([]byte)
		if !ok {
			return errors.New("cbor object encoding of ip6 not a byte array")
		}
		ip := net.IP(v)
		obj.Value = ip.String()
	case OTIP4Addr:
		v, ok := in[1].([]byte)
		if !ok {
			return errors.New("cbor object encoding of ip6 not a byte array")
		}
		ip := net.IP(v)
		obj.Value = ip.String()
	case OTScionAddr6:
		addrStr, ok := in[1].(string)
		if !ok {
			return fmt.Errorf("failed to unmarshal OTScionAddr6: %T", in[1])
		}
		addr, err := snet.AddrFromString(addrStr)
		if err != nil {
			return fmt.Errorf("failed to unmarshal OTScionAddr6: %v", err)
		}
		obj.Value = fmt.Sprintf("%s,[%v]", addr.IA, addr.Host.L3)
	case OTScionAddr4:
		addrStr, ok := in[1].(string)
		if !ok {
			return fmt.Errorf("wrong object value for OTScionAddr4: %T", in[1])
		}
		addr, err := snet.AddrFromString(addrStr)
		if err != nil {
			return fmt.Errorf("failed to unmarshal OTScionAddr4: %v", err)
		}
		obj.Value = fmt.Sprintf("%s,[%v]", addr.IA, addr.Host.L3)
	case OTRedirection:
		obj.Value = in[1]
	case OTDelegation:
		alg, ok := in[1].(int)
		if !ok {
			return errors.New("cbor object encoding of deleg algo not an int")
		}
		kp, ok := in[2].(int)
		if !ok {
			return errors.New("cbor object encoding of deleg phase not an int")
		}
		var key []byte
		switch algorithmTypes.Signature(alg) {
		case algorithmTypes.Ed25519:
			key, ok = in[3].([]byte)
			if !ok {
				return errors.New("cbor object encoding of deleg key not a byte array")
			}
		default:
			return fmt.Errorf("unsupported algorithm: %v", alg)
		}
		pkey := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: algorithmTypes.Signature(alg),
				KeySpace:  keys.RainsKeySpace,
				KeyPhase:  kp,
			},
			Key: ed25519.PublicKey(key),
		}
		obj.Value = pkey
	case OTNameset:
		v, ok := in[1].(string)
		if !ok {
			return errors.New("cbor object encoding of nameset not a string")
		}
		obj.Value = NamesetExpr(v)
	case OTCertInfo:
		proto, ok := in[1].(int)
		if !ok {
			return errors.New("cbor object encoding of cert proto not an int")
		}
		usage, ok := in[2].(int)
		if !ok {
			return errors.New("cbor object encoding of cert usage not an int")
		}
		hash, ok := in[3].(int)
		if !ok {
			return errors.New("cbor object encoding of cert hash not an int")
		}
		data, ok := in[4].([]byte)
		if !ok {
			return errors.New("cbor object encoding of cert data not a byte array")
		}
		co := Certificate{
			Type:     ProtocolType(proto),
			Usage:    CertificateUsage(usage),
			HashAlgo: algorithmTypes.Hash(hash),
			Data:     data,
		}
		obj.Value = co
	case OTServiceInfo:
		name, ok := in[1].(string)
		if !ok {
			return errors.New("cbor object encoding of serv name not an string")
		}
		port, ok := in[2].(int)
		if !ok {
			return errors.New("cbor object encoding of serv port not an int")
		}
		prio, ok := in[3].(int)
		if !ok {
			return errors.New("cbor object encoding of serv prio not an int")
		}
		si := ServiceInfo{
			Name:     name,
			Port:     uint16(port),
			Priority: uint(prio),
		}
		obj.Value = si
	case OTRegistrar:
		obj.Value, ok = in[1].(string)
		if !ok {
			return errors.New("cbor object encoding of serv name not an string")
		}
	case OTRegistrant:
		obj.Value, ok = in[1].(string)
		if !ok {
			return errors.New("cbor object encoding of serv name not an string")
		}
	case OTInfraKey:
		alg, ok := in[1].(int)
		if !ok {
			return errors.New("cbor object encoding of infra algo not an int")
		}
		kp, ok := in[2].(int)
		if !ok {
			return errors.New("cbor object encoding of infra phase not an int")
		}
		var key []byte
		switch algorithmTypes.Signature(alg) {
		case algorithmTypes.Ed25519:
			key, ok = in[3].([]byte)
			if !ok {
				return errors.New("cbor object encoding of infra key not a byte array")
			}
		default:
			return fmt.Errorf("unsupported algorithm: %v", alg)
		}
		pkey := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: algorithmTypes.Signature(alg),
				KeySpace:  keys.RainsKeySpace,
				KeyPhase:  kp,
			},
			Key: ed25519.PublicKey(key),
		}
		obj.Value = pkey
	case OTExtraKey:
		alg, ok := in[1].(int)
		if !ok {
			return errors.New("cbor object encoding of extra algo not an int")
		}
		ks, ok := in[2].(int)
		if !ok {
			return errors.New("cbor object encoding of extra keyspace not an int")
		}
		var key []byte
		switch algorithmTypes.Signature(alg) {
		case algorithmTypes.Ed25519:
			key, ok = in[3].([]byte)
			if !ok {
				return errors.New("cbor object encoding of extra key not a byte array")
			}
		default:
			return fmt.Errorf("unsupported algorithm: %v", alg)
		}
		pkey := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: algorithmTypes.Signature(alg),
				KeySpace:  keys.KeySpaceID(ks),
			},
			Key: ed25519.PublicKey(key),
		}
		obj.Value = pkey
	case OTNextKey:
		alg, ok := in[1].(int)
		if !ok {
			return errors.New("cbor object encoding of nextKey algo not an int")
		}
		kp, ok := in[2].(int)
		if !ok {
			return errors.New("cbor object encoding of nextKey phase not an int")
		}
		vs, ok := in[4].(int)
		if !ok {
			return errors.New("cbor object encoding of nextKey validSince not an int")
		}
		vu, ok := in[5].(int)
		if !ok {
			return errors.New("cbor object encoding of nextKey validUntil not an int")
		}
		var key []byte
		switch algorithmTypes.Signature(alg) {
		case algorithmTypes.Ed25519:
			key, ok = in[3].([]byte)
			if !ok {
				return errors.New("cbor object encoding of nextKey key not a byte array")
			}
		default:
			return fmt.Errorf("unsupported algorithm: %v", alg)
		}
		pkey := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				Algorithm: algorithmTypes.Signature(alg),
				KeySpace:  keys.RainsKeySpace,
				KeyPhase:  kp,
			},
			ValidSince: int64(vs),
			ValidUntil: int64(vu),
			Key:        ed25519.PublicKey(key),
		}
		obj.Value = pkey
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
	case OTScionAddr6:
		addrStr := obj.Value.(string)
		addr, err := snet.AddrFromString(addrStr)
		if err != nil {
			return err
		}
		res = []interface{}{OTScionAddr6, fmt.Sprintf("%s,[%v]", addr.IA, addr.Host.L3)}
	case OTScionAddr4:
		addrStr := obj.Value.(string)
		addr, err := snet.AddrFromString(addrStr)
		if err != nil {
			return err
		}
		res = []interface{}{OTScionAddr4, fmt.Sprintf("%s,[%v]", addr.IA, addr.Host.L3)}
	case OTRedirection:
		res = []interface{}{OTRedirection, obj.Value}
	case OTDelegation:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return fmt.Errorf("expected OTDelegation value to be PublicKey but got: %T", obj.Value)
		}
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTDelegation, int(pkey.Algorithm), pkey.KeyPhase, b}
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
			return fmt.Errorf("expected OTInfraKey value to be PublicKey but got: %T", obj.Value)
		}
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTInfraKey, int(pkey.Algorithm), pkey.KeyPhase, b}
	case OTExtraKey:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return fmt.Errorf("expected OTExtraKey value to be PublicKey but got: %T", obj.Value)
		}
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTExtraKey, int(pkey.Algorithm), int(pkey.KeySpace), b}
	case OTNextKey:
		pkey, ok := obj.Value.(keys.PublicKey)
		if !ok {
			return fmt.Errorf("expected OTNextKey value to be PublicKey but got: %T", obj.Value)
		}
		b := pubkeyToCBORBytes(pkey)
		res = []interface{}{OTNextKey, int(pkey.Algorithm), pkey.KeyPhase, b, pkey.ValidSince, pkey.ValidUntil}
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

//go:generate stringer -type=Type
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
	OTScionAddr6  Type = 14
	OTScionAddr4  Type = 15
)

//ParseTypes returns the object type(s) specified in qType
func ParseTypes(qType string) ([]Type, error) {
	switch qType {
	case "name":
		return []Type{OTName}, nil
	case "ip6":
		return []Type{OTIP6Addr}, nil
	case "ip4":
		return []Type{OTIP4Addr}, nil
	case "scionip6":
		return []Type{OTScionAddr6}, nil
	case "scionip4":
		return []Type{OTScionAddr4}, nil
	case "redir":
		return []Type{OTRedirection}, nil
	case "deleg":
		return []Type{OTDelegation}, nil
	case "nameset":
		return []Type{OTNameset}, nil
	case "cert":
		return []Type{OTCertInfo}, nil
	case "srv":
		return []Type{OTServiceInfo}, nil
	case "regr":
		return []Type{OTRegistrar}, nil
	case "regt":
		return []Type{OTRegistrant}, nil
	case "infra":
		return []Type{OTInfraKey}, nil
	case "extra":
		return []Type{OTExtraKey}, nil
	case "next":
		return []Type{OTNextKey}, nil
	case "any":
		return AllTypes(), nil
	}
	return []Type{Type(-1)}, fmt.Errorf("%s is not a query option", qType)
}

//TypeString returns the CLI type string corresponding to the object type specified in qType
func (t Type) CLIString() string {
	switch t {
	case OTName:
		return "name"
	case OTIP6Addr:
		return "ip6"
	case OTIP4Addr:
		return "ip4"
	case OTScionAddr6:
		return "scionip6"
	case OTScionAddr4:
		return "scionip4"
	case OTRedirection:
		return "redir"
	case OTDelegation:
		return "deleg"
	case OTNameset:
		return "nameset"
	case OTCertInfo:
		return "cert"
	case OTServiceInfo:
		return "srv"
	case OTRegistrar:
		return "regr"
	case OTRegistrant:
		return "regt"
	case OTInfraKey:
		return "infra"
	case OTExtraKey:
		return "extra"
	case OTNextKey:
		return "next"
	}
	return t.String()
}

//AllTypes returns all object types.
func AllTypes() []Type {
	return []Type{OTName, OTIP6Addr, OTIP4Addr, OTRedirection,
		OTDelegation, OTNameset, OTCertInfo, OTServiceInfo,
		OTRegistrar, OTRegistrant, OTInfraKey, OTExtraKey,
		OTNextKey, OTScionAddr6, OTScionAddr4}
}

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

//go:generate stringer -type=ProtocolType
const (
	PTUnspecified ProtocolType = 0
	PTTLS         ProtocolType = 1
)

//CertificateUsage is an identifier for a certificate usage. The ID is chosen according to the RAINS Protocol Specification.
type CertificateUsage int

//go:generate stringer -type=CertificateUsage
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
