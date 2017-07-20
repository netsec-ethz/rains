package rainslib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//Object contains a Value of to the specified Type
type Object struct {
	Type  ObjectType
	Value interface{}
}

//Sort sorts the content of o lexicographically.
func (o *Object) Sort() {
	if name, ok := o.Value.(NameObject); ok {
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
	case NameObject:
		if v2, ok := object.Value.(NameObject); ok {
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
	case PublicKey:
		if v2, ok := object.Value.(PublicKey); ok {
			return v1.CompareTo(v2)
		}
		logObjectTypeAssertionFailure(object.Type, object.Value)
	case NamesetExpression:
		if v2, ok := object.Value.(NamesetExpression); ok {
			if v1 < v2 {
				return -1
			} else if v1 > v2 {
				return 1
			}
		} else {
			logObjectTypeAssertionFailure(object.Type, object.Value)
		}
	case CertificateObject:
		if v2, ok := object.Value.(CertificateObject); ok {
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
func logObjectTypeAssertionFailure(t ObjectType, value interface{}) {
	log.Error("Object Type and corresponding type assertion of object's value do not match",
		"objectType", t, "objectValueType", fmt.Sprintf("%T", value))
}

//ObjectType identifier for object types. ID chosen according to RAINS Protocol Specification
type ObjectType int

//String returns the ID as a string
func (o ObjectType) String() string {
	return strconv.Itoa(int(o))
}

const (
	OTName        ObjectType = 1
	OTIP6Addr     ObjectType = 2
	OTIP4Addr     ObjectType = 3
	OTRedirection ObjectType = 4
	OTDelegation  ObjectType = 5
	OTNameset     ObjectType = 6
	OTCertInfo    ObjectType = 7
	OTServiceInfo ObjectType = 8
	OTRegistrar   ObjectType = 9
	OTRegistrant  ObjectType = 10
	OTInfraKey    ObjectType = 11
	OTExtraKey    ObjectType = 12
	OTNextKey     ObjectType = 13
)

//NameObject contains a name associated with a name as an alias. Types specifies for which object types the alias is valid
type NameObject struct {
	Name string
	//Types for which the Name is valid
	Types []ObjectType
}

//CompareTo compares two nameObjects and returns 0 if they are equal, 1 if n is greater than nameObject and -1 if n is smaller than nameObject
func (n NameObject) CompareTo(nameObj NameObject) int {
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

//KeySpaceID identifies a key space
type KeySpaceID int

const (
	RainsKeySpace KeySpaceID = 0
)

//SignatureAlgorithmType specifies a signature algorithm type
type SignatureAlgorithmType int

const (
	Ed25519  SignatureAlgorithmType = 1
	Ed448    SignatureAlgorithmType = 2
	Ecdsa256 SignatureAlgorithmType = 3
	Ecdsa384 SignatureAlgorithmType = 4
)

func (sigAlgo SignatureAlgorithmType) String() string {
	return strconv.Itoa(int(sigAlgo))
}

//HashAlgorithmType specifies a hash algorithm type
type HashAlgorithmType int

const (
	NoHashAlgo HashAlgorithmType = 0
	Sha256     HashAlgorithmType = 1
	Sha384     HashAlgorithmType = 2
	Sha512     HashAlgorithmType = 3
)

//PublicKeyID contains all necessary information to distinguish different public keys from the same
//authority
type PublicKeyID struct {
	//Algorithm determines the signature algorithm to be used for signing and verification
	Algorithm SignatureAlgorithmType
	//KeySpace is an identifier of a key space
	KeySpace KeySpaceID
	//KeyPhase defines the keyPhase in which this public key is valid
	KeyPhase int
}

func (p PublicKeyID) String() string {
	return fmt.Sprintf("%s %v %d", p.Algorithm, p.KeySpace, p.KeyPhase)
}

//PublicKey contains information about a public key
type PublicKey struct {
	PublicKeyID
	ValidSince int64
	ValidUntil int64
	Key        interface{}
}

//CompareTo compares two publicKey objects and returns 0 if they are equal, 1 if p is greater than pkey and -1 if p is smaller than pkey
func (p PublicKey) CompareTo(pkey PublicKey) int {
	if p.Algorithm < pkey.Algorithm {
		return -1
	} else if p.Algorithm > pkey.Algorithm {
		return 1
	} else if p.KeySpace < pkey.KeySpace {
		return -1
	} else if p.KeySpace > pkey.KeySpace {
		return 1
	} else if p.ValidSince < pkey.ValidSince {
		return -1
	} else if p.ValidSince > pkey.ValidSince {
		return 1
	} else if p.ValidUntil < pkey.ValidUntil {
		return -1
	} else if p.ValidUntil > pkey.ValidUntil {
		return 1
	} else if p.KeyPhase < pkey.KeyPhase {
		return -1
	} else if p.KeyPhase > pkey.KeyPhase {
		return 1
	}
	switch k1 := p.Key.(type) {
	case ed25519.PublicKey:
		if k2, ok := pkey.Key.(ed25519.PublicKey); ok {
			return bytes.Compare(k1, k2)
		}
		log.Error("PublicKey.Key Type does not match algorithmIdType", "algoType", pkey.Algorithm, "KeyType", fmt.Sprintf("%T", pkey.Key))
	default:
		log.Warn("Unsupported public key type", "type", fmt.Sprintf("%T", p.Key))
	}
	return 0
}

//String implements Stringer interface
func (p PublicKey) String() string {
	keyString := ""
	switch k1 := p.Key.(type) {
	case ed25519.PublicKey:
		keyString = hex.EncodeToString(k1)
	default:
		log.Warn("Unsupported public key type", "type", fmt.Sprintf("%T", p.Key))
	}
	return fmt.Sprintf("{%d %d %d %d %d %s}",
		p.Algorithm, p.KeySpace, p.ValidSince, p.ValidUntil, p.KeyPhase, keyString)
}

//NamesetExpression encodes a modified POSIX Extended Regular Expression format
type NamesetExpression string

//CertificateObject contains a certificate and its meta data (type, usage and hash algorithm identifier)
type CertificateObject struct {
	Type     ProtocolType
	Usage    CertificateUsage
	HashAlgo HashAlgorithmType
	Data     []byte
}

//CompareTo compares two certificateObject objects and returns 0 if they are equal, 1 if c is greater than cert and -1 if c is smaller than cert
func (c CertificateObject) CompareTo(cert CertificateObject) int {
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
func (c CertificateObject) String() string {
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

//NetworkAddrType enumerates network address types
type NetworkAddrType int

//run 'jsonenums -type=NetworkAddrType' in this directory if a new networkAddrType is added [source https://github.com/campoy/jsonenums]
const (
	TCP NetworkAddrType = iota + 1
)
