package generate

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
)

type Query struct {
	Info     query.Name
	SendTime int64 //Nanoseconds since 1.1.1970
}

type Queries struct {
	Trace []Query
	Dst   int //resolver's identifier
	ID    int //client ID
}

type NameType struct {
	Name string
	Type object.Type
}

func Traces(clientToResolver map[int]int, maxQueriesPerClient int, nameTypes []NameType, start, end, seed int64,
	zipfS float64) {
	traces := []Queries{}
	zipf := rand.NewZipf(rand.New(rand.NewSource(seed)), zipfS, 1, uint64(len(nameTypes)))
	for client, resolver := range clientToResolver {
		trace := Queries{
			Dst: resolver,
			ID:  client,
		}
		for i := 0; i < rand.Intn(maxQueriesPerClient); i++ {
			index := int(zipf.Uint64())
			q := Query{SendTime: start + rand.Int63n(end-start)}
			q.Info = query.Name{
				Context:    ".", //TODO CFE currently only global context is supported.
				Expiration: q.SendTime/int64(time.Second) + 2,
				Name:       nameTypes[index].Name,
				Options:    []query.Option{query.QOMinE2ELatency},
				Types:      []object.Type{nameTypes[index].Type},
			}
			trace.Trace = append(trace.Trace, q)
		}
		traces = append(traces, trace)
	}
	encoding, _ := json.Marshal(traces)
	if err := ioutil.WriteFile("traces/traces.json", encoding, 0600); err != nil {
		panic(err.Error())
	}
}

//ClientResolverMapping returns a mapping from clients to resolvers.
func ClientResolverMapping(clientIDs, resolverIDs []int) map[int]int {
	res := make(map[int]int)
	for _, client := range clientIDs {
		res[client] = resolverIDs[rand.Intn(len(resolverIDs))]
	}
	return res
}
