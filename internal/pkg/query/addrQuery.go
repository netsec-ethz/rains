package query

import (
	"fmt"
	"net"
	"sort"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/object"
)

//Address contains information about the address query
type Address struct {
	SubjectAddr *net.IPNet
	Context     string
	Types       []object.Type
	Expiration  int64 //Unix seconds
	Options     []Option
}

// UnmarshalMap decodes the output from the CBOR decoder into this struct.
func (q *Address) UnmarshalMap(m map[int]interface{}) error {
	//TODO CFE to implement
	return nil
}

func (q *Address) MarshalCBOR(w *borat.CBORWriter) error {
	//TODO CFE to implement
	return nil
}

//GetContext returns q's context
func (q *Address) GetContext() string {
	return q.Context
}

//GetExpiration returns q's expiration
func (q *Address) GetExpiration() int64 {
	return q.Expiration
}

//ContainsOption returns true if the address query contains the given query option.
func (q *Address) ContainsOption(option Option) bool {
	return containsOption(option, q.Options)
}

//Sort sorts the content of the addressQuery lexicographically.
func (q *Address) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two addressQueries and returns 0 if they are equal, 1 if q is greater than
//query and -1 if q is smaller than query
func (q *Address) CompareTo(query *Address) int {
	if q.SubjectAddr.String() < query.SubjectAddr.String() {
		return -1
	} else if q.SubjectAddr.String() > query.SubjectAddr.String() {
		return 1
	} else if q.Context < query.Context {
		return -1
	} else if q.Context > query.Context {
		return 1
	} else if len(q.Types) < len(query.Types) {
		return -1
	} else if len(q.Types) > len(query.Types) {
		return 1
	}
	for i, o := range q.Types {
		if o < query.Types[i] {
			return -1
		} else if o > query.Types[i] {
			return 1
		}
	}
	if q.Expiration < query.Expiration {
		return -1
	} else if q.Expiration > query.Expiration {
		return 1
	} else if len(q.Options) < len(query.Options) {
		return -1
	} else if len(q.Options) > len(query.Options) {
		return 1
	}
	for i, o := range q.Options {
		if o < query.Options[i] {
			return -1
		} else if o > query.Options[i] {
			return 1
		}
	}
	return 0
}

//String implements Stringer interface
func (q *Address) String() string {
	if q == nil {
		return "AddressQuery:nil"
	}
	return fmt.Sprintf("AddressQuery:[SA=%s CTX=%s TYPE=%v EXP=%d OPT=%v]",
		q.SubjectAddr, q.Context, q.Types, q.Expiration, q.Options)
}
