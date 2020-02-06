// Code generated by "stringer -type=Type"; DO NOT EDIT.

package rains

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[OTName-1]
	_ = x[OTIP6Addr-2]
	_ = x[OTIP4Addr-3]
	_ = x[OTRedirection-4]
	_ = x[OTDelegation-5]
	_ = x[OTNameset-6]
	_ = x[OTCertInfo-7]
	_ = x[OTServiceInfo-8]
	_ = x[OTRegistrar-9]
	_ = x[OTRegistrant-10]
	_ = x[OTInfraKey-11]
	_ = x[OTExtraKey-12]
	_ = x[OTNextKey-13]
	_ = x[OTScionAddr-14]
}

const _Type_name = "OTNameOTIP6AddrOTIP4AddrOTRedirectionOTDelegationOTNamesetOTCertInfoOTServiceInfoOTRegistrarOTRegistrantOTInfraKeyOTExtraKeyOTNextKeyOTScionAddr"

var _Type_index = [...]uint8{0, 6, 15, 24, 37, 49, 58, 68, 81, 92, 104, 114, 124, 133, 144}

func (i Type) String() string {
	i -= 1
	if i < 0 || i >= Type(len(_Type_index)-1) {
		return "Type(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _Type_name[_Type_index[i]:_Type_index[i+1]]
}
