package libresolve

import (
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/section"

	"github.com/netsec-ethz/rains/internal/pkg/message"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"

	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

func createResolver() *Resolver {
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

func createQuery() *query.Name {
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
	resolver := createResolver()
	q := createQuery()
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
	resolver := createResolver()
	resolver.RootNameServers = []net.Addr{&net.IPAddr{IP: net.IPv4(127, 0, 0, 1), Zone: "test-zone"}}
	numberOfMessagesSent := 0
	resolver.sendQueryFcn = func(msg message.Message, addr net.Addr, timeout time.Duration) (message.Message, error) {
		if addr.(*net.IPAddr) == nil || addr.(*net.IPAddr).Zone != "test-zone" {
			t.Fatalf("Resolver contacted some other server")
		}
		numberOfMessagesSent++
		return message.Message{Content: []section.Section{&assertion}}, nil
	}
	resolver.handleAnswerFcn = func(r *Resolver, msg message.Message, q *query.Name, recurseCount int) (
		isFinal bool, isRedir bool, redirMap map[string]string, srvMap map[string]object.ServiceInfo,
		ipMap map[string]string, nameMap map[string]object.Name) {
		isFinal = true
		return
	}
	q := createQuery()
	ans, err := resolver.recursiveResolve(q, 0)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ans.Content) != 1 || ans.Content[0].(*section.Assertion) == nil || ans.Content[0].(*section.Assertion).FQDN() != assertion.FQDN() {
		t.Errorf("Wrong answer received, fqdn=%s", assertion.FQDN())
	}
	if numberOfMessagesSent != 1 {
		log.Fatalf("Should have contacted 1 root server, but did it %d times", numberOfMessagesSent)
	}
}
