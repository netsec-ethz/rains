package generate

import (
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/simulation"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

func Traces(clientToResolver map[string]simulation.ClientInfo, globalNames []simulation.NameType, localNames [][]simulation.NameType, conf simulation.Config) []simulation.Queries {
	traces := []simulation.Queries{}
	zipf := rand.NewZipf(rand.New(rand.NewSource(conf.Zipfs.GlobalQuery.Seed)), conf.Zipfs.GlobalQuery.S, 1, uint64(len(globalNames)-1))
	localZipfs := make([]*rand.Zipf, len(localNames))
	for i, names := range localNames {
		localZipfs[i] = rand.NewZipf(rand.New(rand.NewSource(conf.Zipfs.LocalQuery.Seed)), conf.Zipfs.LocalQuery.S, 1, uint64(len(names)-1))
	}
	for client, info := range clientToResolver {
		trace := simulation.Queries{
			Dst: info.Resolver,
			ID:  client,
		}
		for i := 0; i < rand.Intn(conf.MaxQueriesPerClient); i++ {
			nameType := simulation.NameType{}
			if rand.Intn(101) < conf.FractionLocalQueries {
				nameType = localNames[info.TLD][int(localZipfs[info.TLD].Uint64())]
			} else {
				nameType = globalNames[int(zipf.Uint64())]
			}
			q := simulation.Message{SendTime: conf.Start + rand.Int63n(conf.End-conf.Start)}
			intermediateNames := strings.Split(nameType.Name, ".")
			intermediateNames[0] = "NonExistentName"
			qName := strings.Join(intermediateNames, ".")
			if (i+1)%conf.FractionNegQuery != 0 {
				qName = nameType.Name
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
						Types:      []object.Type{nameType.Type},
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
