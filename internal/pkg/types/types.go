package types

//NetworkAddrType enumerates network address types
type NetworkAddrType int

//run 'go generate' in this directory if a new networkAddrType is added [source https://github.com/campoy/jsonenums]
//go:generate jsonenums -type=NetworkAddrType
const (
	TCP NetworkAddrType = iota + 1
)
