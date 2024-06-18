package section

import (
	"time"

	cbor "github.com/britram/borat"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

// Section can be either an Assertion, Shard, Zone, Query, Notification, AddressAssertion, AddressZone, AddressQuery section
type Section interface {
	Sort()
	String() string
	MarshalCBOR(w *cbor.CBORWriter) error
	UnmarshalMap(m map[int]interface{}) error
}

// WithSig is an interface for a section protected by a signature. In the current
// implementation it can be an Assertion, Shard, Zone, AddressAssertion, AddressZone
type WithSig interface {
	Section
	AllSigs() []signature.Sig
	Sigs(keyspace keys.KeySpaceID) []signature.Sig
	AddSig(sig signature.Sig)
	DeleteSig(index int)
	DeleteAllSigs()
	GetContext() string
	GetSubjectZone() string
	UpdateValidity(validSince, validUntil int64, maxValidity time.Duration)
	ValidSince() int64
	SetValidSince(int64)
	ValidUntil() int64
	SetValidUntil(int64)
	Hash() string
	IsConsistent() bool
	NeededKeys(map[signature.MetaData]bool)
	AddSigInMarshaller()
	DontAddSigInMarshaller()
}

// WithSigForward can be either an Assertion, Shard or Zone
type WithSigForward interface {
	WithSig
	Interval
}

// Query is the interface for a query section. In the current implementation it can be
// a query or an addressQuery
type Query interface {
	GetContext() string
	GetExpiration() int64
}

// Interval defines an interval over strings
type Interval interface {
	//Begin of the interval
	Begin() string
	//End of the interval
	End() string
}

// Hasher can be implemented by objects that are not natively hashable.
// For an object to be a map key (or a part thereof), it must be hashable.
type Hasher interface {
	//Hash must return a string uniquely identifying the object
	//It must hold for all objects that o1 == o2 iff o1.Hash() == o2.Hash()
	Hash() string
}
