package object

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
)

//Object contains a Value of to the specified Type
type Object struct {
	Type  Type
	Value interface{}
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
		log.Warn("Unsupported object.Value type", "type", fmt.Sprintf("%T", o.Value))
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

//ContainsType returns the first object with oType and true if objects contains at least one
func ContainsType(objects []Object, oType Type) (Object, bool) {
	for _, o := range objects {
		if o.Type == oType {
			return o, true
		}
	}
	return Object{}, false
}
