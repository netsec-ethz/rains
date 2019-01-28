package libresolve

import (
	"net"
	"strings"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"

	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

func TestRecursiveResolve(t *testing.T) {
	resolver := &Resolver{
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
	q := query.Name{
		Context:     "",
		Name:        "",
		Types:       []object.Type{object.OTName},
		Expiration:  100,
		Options:     []query.Option{},
		KeyPhase:    1,
		CurrentTime: 10,
	}
	_, err := resolver.recursiveResolve(&q, 1)
	if err == nil {
		t.Error("Should fail because max recursion depth is 1")
	} else if !strings.HasPrefix(err.Error(), "Maximum number of recursive calls") {
		t.Errorf("Unexpected error not about max. recursive calls. This is the error: %v", err)
	}
	_, err = resolver.recursiveResolve(&q, 0)
	if err == nil || strings.HasPrefix(err.Error(), "Maximum number of recursive calls") {
		t.Errorf("Unexpected error about max. recursive calls. This is the error: %v", err)
	}
}
