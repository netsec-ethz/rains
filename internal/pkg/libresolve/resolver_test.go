package libresolve

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"

	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

func newResolver() *Resolver {
	return &Resolver{
		RootNameServers: []net.Addr{},
		Forwarders:      []net.Addr{},
		Mode:            Recursive,
		InsecureTLS:     defaultInsecureTLS,
		DialTimeout:     defaultTimeout,
		FailFast:        defaultFailFast,
		Delegations:     safeHashMap.New(),
		Connections:     cache.NewConnection(1),
		MaxCacheValidity: util.MaxCacheValidity{
			AssertionValidity: 100,
			ShardValidity:     100,
			PshardValidity:    100,
			ZoneValidity:      100,
		},
		MaxRecursiveCount: 1,
	}
}

func newQuery() *query.Name {
	return &query.Name{
		Context:     "",
		Name:        "",
		Types:       []object.Type{object.OTName},
		Expiration:  100,
		Options:     []query.Option{},
		KeyPhase:    1,
		CurrentTime: 10,
	}
}

func TestRecursiveResolveMaxDepth(t *testing.T) {
	resolver := newResolver()
	q := newQuery()
	_, err := resolver.recursiveResolve(q, 1)
	if err == nil {
		t.Error("Should fail because max recursion depth is 1")
	} else if !strings.HasPrefix(err.Error(), "Maximum number of recursive calls") {
		t.Errorf("Unexpected error not about max. recursive calls. This is the error: %v", err)
	}
	_, err = resolver.recursiveResolve(q, 0)
	if err == nil || strings.HasPrefix(err.Error(), "Maximum number of recursive calls") {
		t.Errorf("Unexpected error about max. recursive calls. This is the error: %v", err)
	}
}

func TestRecursiveResolveQueriesRoot(t *testing.T) {
	assertion := section.Assertion{SubjectZone: ".", SubjectName: "ch"}
	resolver := newResolver()
	resolver.RootNameServers = []net.Addr{&net.IPAddr{IP: net.IPv4(127, 0, 0, 11), Zone: "test-zone"}}
	numberOfMessagesSent := 0
	resolver.sendQuery = func(msg message.Message, addr net.Addr, timeout time.Duration) (message.Message, error) {
		if ipAddr, ok := addr.(*net.IPAddr); !ok || !ipAddr.IP.Equal(net.IPv4(127, 0, 0, 11)) || ipAddr.Zone != "test-zone" {
			t.Fatalf("Resolver contacted some other server at %v", ipAddr)
		}
		numberOfMessagesSent++
		return message.Message{Content: []section.Section{&assertion}}, nil
	}
	resolver.handleAnswer = func(r *Resolver, msg message.Message, q *query.Name, recurseCount int) (
		isFinal bool, isRedir bool, redirMap map[string]string, srvMap map[string]object.ServiceInfo,
		ipMap map[string]string, nameMap map[string]object.Name) {
		isFinal = true
		return
	}
	q := newQuery()
	ans, err := resolver.recursiveResolve(q, 0)
	if err != nil {
		t.Fatalf("The call to recursiveResolve finished with an error: %v", err)
	}
	if len(ans.Content) != 1 || ans.Content[0].(*section.Assertion) == nil || ans.Content[0].(*section.Assertion).FQDN() != assertion.FQDN() {
		t.Fatalf("Wrong answer received, FQDN: %q", assertion.FQDN())
	}
	if numberOfMessagesSent != 1 {
		t.Fatalf("Should have contacted 1 root server, but did it %d times", numberOfMessagesSent)
	}
}
