package query

import (
	"errors"
	"fmt"
	"sort"

	cbor "github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/object"
)

//Name contains information about the query
type Name struct {
	Context     string
	Name        string
	Types       []object.Type
	Expiration  int64 //unix seconds
	Options     []Option
	KeyPhase    int
	CurrentTime int64
}

// UnmarshalMap unpacks a CBOR marshaled map to this struct.
func (q *Name) UnmarshalMap(m map[int]interface{}) error {
	if n, ok := m[6].(string); ok {
		q.Context = n
	} else {
		return errors.New("cbor query map does not contain a context name")
	}
	if n, ok := m[8].(string); ok {
		q.Name = n
	} else {
		return errors.New("cbor query map does not contain a fqdn name")
	}
	q.Types = make([]object.Type, 0)
	if types, ok := m[10].([]interface{}); ok {
		for _, qt := range types {
			t, ok := qt.(int)
			if !ok {
				return errors.New("cbor query encoding of a type array's element should be an int")
			}
			q.Types = append(q.Types, object.Type(t))
		}
	} else {
		return errors.New("cbor query map does not contain a types array")
	}
	if exp, ok := m[12].(int); ok {
		q.Expiration = int64(exp)
	} else {
		return errors.New("cbor query map does not contain an expiration")
	}
	q.Options = make([]Option, 0)
	if opts, ok := m[13].([]interface{}); ok {
		for _, opt := range opts {
			o, ok := opt.(int)
			if !ok {
				return errors.New("cbor query encoding of a option array's element should be an int")
			}
			q.Options = append(q.Options, Option(o))
		}
	} else {
		return errors.New("cbor query map does not contain a query options array")
	}
	if ct, ok := m[14].(int); ok {
		q.CurrentTime = int64(ct)
	} else {
		return errors.New("cbor query map does not contain the current time")
	}
	var ok bool
	q.KeyPhase, ok = m[17].(int)
	if !ok {
		return errors.New("cbor query encoding of the key phase should be an int")
	}
	return nil
}

// MarshalCBOR implements the CBORMarshaler interface.
func (q *Name) MarshalCBOR(w *cbor.CBORWriter) error {
	m := make(map[int]interface{})
	m[6] = q.Context
	m[8] = q.Name
	qtypes := make([]int, len(q.Types))
	for i, qtype := range q.Types {
		qtypes[i] = int(qtype)
	}
	m[10] = qtypes
	m[12] = q.Expiration
	qopts := make([]int, len(q.Options))
	for i, qopt := range q.Options {
		qopts[i] = int(qopt)
	}
	m[13] = qopts
	m[14] = q.CurrentTime
	m[17] = q.KeyPhase
	return w.WriteIntMap(m)
}

//GetContext returns q's context
func (q *Name) GetContext() string {
	return q.Context
}

//GetExpiration returns q's expiration
func (q *Name) GetExpiration() int64 {
	return q.Expiration
}

//ContainsOption returns true if the query contains the given query option.
func (q *Name) ContainsOption(option Option) bool {
	return containsOption(option, q.Options)
}

//containsOption return true if option is contained in options
func containsOption(option Option, options []Option) bool {
	for _, opt := range options {
		if opt == option {
			return true
		}
	}
	return false
}

//Sort sorts the content of the query lexicographically.
func (q *Name) Sort() {
	sort.Slice(q.Options, func(i, j int) bool { return q.Options[i] < q.Options[j] })
}

//CompareTo compares two queries and returns 0 if they are equal, 1 if q is greater than query and
//-1 if q is smaller than query
func (q *Name) CompareTo(query *Name) int {
	if q.Context < query.Context {
		return -1
	} else if q.Context > query.Context {
		return 1
	} else if q.Name < query.Name {
		return -1
	} else if q.Name > query.Name {
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
	if q.CurrentTime < query.CurrentTime {
		return -1
	} else if q.CurrentTime > query.CurrentTime {
		return 1
	} else if q.KeyPhase < query.KeyPhase {
		return -1
	} else if q.KeyPhase > query.KeyPhase {
		return 1
	}
	return 0
}

//String implements Stringer interface
func (q *Name) String() string {
	if q == nil {
		return "Query:nil"
	}
	return fmt.Sprintf("Query:[CTX=%s NA=%s TYPE=%v EXP=%d OPT=%v CT=%d KP=%d]",
		q.Context, q.Name, q.Types, q.Expiration, q.Options, q.CurrentTime, q.KeyPhase)
}

//Option enables a client or server to specify performance/privacy tradeoffs
type Option int

//go:generate stringer -type=Option
const (
	QOMinE2ELatency            Option = 1
	QOMinLastHopAnswerSize     Option = 2
	QOMinInfoLeakage           Option = 3
	QOCachedAnswersOnly        Option = 4
	QOExpiredAssertionsOk      Option = 5
	QOTokenTracing             Option = 6
	QONoVerificationDelegation Option = 7
	QONoProactiveCaching       Option = 8
	QOMaxFreshness             Option = 9
)
