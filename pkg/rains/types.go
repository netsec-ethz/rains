package rains

import (
	"fmt"

	"github.com/netsec-ethz/rains/internal/pkg/object"
)

// Type identifier for object connection. ID chosen according to RAINS Protocol Specification
type Type int

//go:generate stringer -type=Type
const (
	OTName Type = iota + 1
	OTIP6Addr
	OTIP4Addr
	OTRedirection
	OTDelegation
	OTNameset
	OTCertInfo
	OTServiceInfo
	OTRegistrar
	OTRegistrant
	OTInfraKey
	OTExtraKey
	OTNextKey
	OTScionAddr6
	OTScionAddr4
)

// ParseTypes returns the object type(s) specified in qType
func ParseTypes(t string) ([]Type, error) {
	switch t {
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
	return []Type{Type(-1)}, fmt.Errorf("%s is not a object type", t)
}

// CLIString returns the CLI type string corresponding to the object type specified in t
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
	default:
		return t.String()
	}
}

//AllTypes returns all object types
func AllTypes() []Type {
	return []Type{OTName, OTIP6Addr, OTIP4Addr, OTRedirection,
		OTDelegation, OTNameset, OTCertInfo, OTServiceInfo,
		OTRegistrar, OTRegistrant, OTInfraKey, OTExtraKey,
		OTNextKey, OTScionAddr6, OTScionAddr4}
}

func convertTyps(types []Type) []object.Type {
	var oTypes []object.Type
	for _, t := range types {
		oTypes = append(oTypes, object.Type(t))
	}
	return oTypes
}
