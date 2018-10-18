package generate

import (
	"math/rand"
	"sort"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

type Message struct {
	Info     message.Message
	SendTime int64 //Nanoseconds since 1.1.1970
}

type Queries struct {
	Trace []Message
	Dst   string //resolver's identifier
	ID    string //client ID
}

type NameType struct {
	Name string
	Type object.Type
}

type NameIPAddr struct {
	Name   string
	IPAddr string
}

func Traces(clientToResolver map[string]string, maxQueriesPerClient, fractionNegQuery int,
	nameTypes []NameType, start, end, seed int64, zipfS float64) []Queries {
	traces := []Queries{}
	zipf := rand.NewZipf(rand.New(rand.NewSource(seed)), zipfS, 1, uint64(len(nameTypes)))
	for client, resolver := range clientToResolver {
		trace := Queries{
			Dst: resolver,
			ID:  client,
		}
		for i := 0; i < rand.Intn(maxQueriesPerClient); i++ {
			index := int(zipf.Uint64())
			q := Message{SendTime: start + rand.Int63n(end-start)}
			qName := "NonExistentName"
			if (i+1)%fractionNegQuery != 0 {
				qName = nameTypes[index].Name
			}
			q.Info = message.Message{
				Capabilities: []message.Capability{message.NoCapability},
				Token:        token.New(),
				Content: []section.Section{
					&query.Name{
						Context:    ".", //TODO CFE currently only global context is supported.
						Expiration: q.SendTime/int64(time.Second) + 2,
						Name:       qName,
						Options:    []query.Option{query.QOMinE2ELatency},
						Types:      []object.Type{nameTypes[index].Type},
					},
				},
			}
			trace.Trace = append(trace.Trace, q)
		}
		sort.Slice(trace.Trace, func(i, j int) bool { return trace.Trace[i].SendTime < trace.Trace[j].SendTime })
		traces = append(traces, trace)
	}
	/*encoding, _ := json.Marshal(traces)
	if err := ioutil.WriteFile("traces/traces.json", encoding, 0600); err != nil {
		panic(err.Error())
	}*/
	return traces
}

//ClientResolverMapping returns a mapping from clients to resolvers.
func ClientResolverMapping(clientIDs, resolverIDs []int) map[int]int {
	res := make(map[int]int)
	for _, client := range clientIDs {
		res[client] = resolverIDs[rand.Intn(len(resolverIDs))]
	}
	return res
}
