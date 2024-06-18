package rains

import (
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
	OTScionAddr
)

// AllTypes returns all object types
func AllTypes() []Type {
	return []Type{OTName, OTIP6Addr, OTIP4Addr, OTRedirection,
		OTDelegation, OTNameset, OTCertInfo, OTServiceInfo,
		OTRegistrar, OTRegistrant, OTInfraKey, OTExtraKey,
		OTNextKey, OTScionAddr}
}

func convertTyps(types []Type) []object.Type {
	var oTypes []object.Type
	for _, t := range types {
		oTypes = append(oTypes, object.Type(t))
	}
	return oTypes
}
