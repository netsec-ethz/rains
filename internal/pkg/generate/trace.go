package generate

import (
	"math/rand"

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

func Traces(clientToResolver map[int]int, maxQueriesPerClient int, names []string) {
	traces := []Queries{}
	for client, resolver := range clientToResolver {
		trace := Queries{
			Dst: resolver,
			ID:  client,
		}
		trace.Trace = make([]Query, rand.Intn(maxQueriesPerClient))
		for _, q := range trace.Trace {
			//Generate query data
		}
		traces = append(traces, trace)
	}
	print(traces)
}

//ClientResolverMapping returns a mapping from clients to resolvers.
func ClientResolverMapping(clientIDs, resolverIDs []int) map[int]int {
	res := make(map[int]int)
	for _, client := range clientIDs {
		res[client] = resolverIDs[rand.Intn(len(resolverIDs))]
	}
	return res
}
