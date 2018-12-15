package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	name            = flag.String("name", "", "Name to query the server for.")
	context         = flag.String("context", ".", "Context in which to query.")
	rootServer      = flag.String("root", "", "Comma separated list of root resolvers to query.")
	fwdServer       = flag.String("fwd", "", "Comma separated list of recursive resolvers to query.")
	rootServerSCION = flag.String("root_scion", "", "SCION root resolver to query.")
	fwdServerSCION  = flag.String("fwd_scion", "", "SCION forwarding resolver to query.")
	insecureTLS     = flag.Bool("insecureTLS", false, "Whether to validate the TLS certificate of the server.")
)

func main() {
	flag.Parse()
	log.Info("Starting resolver client.")
	if *name == "" {
		log.Error("-name flag must be specified.")
	}
	var resolver *libresolve.Resolver
	mode := libresolve.Recursive
	var roots []connection.Info
	var fwds []connection.Info
	for _, rs := range strings.Split(*rootServer, ",") {
		tcpaddr, err := net.ResolveTCPAddr("", rs)
		if err != nil {
			log.Warn("failed to resolve root server TCP address", "err", err)
			continue
		}
		roots = append(roots, connection.Info{
			Type:    connection.TCP,
			TCPAddr: tcpaddr,
		})
	}
	for _, fs := range strings.Split(*fwdServer, ",") {
		tcpaddr, err := net.ResolveTCPAddr("", fs)
		if err != nil {
			log.Warn("failed to resolve forwarding server TCP address", "err", err)
			continue
		}
		mode = libresolve.Forward
		fwds = append(fwds, connection.Info{
			Type:    connection.TCP,
			TCPAddr: tcpaddr,
		})
	}
	scionFromStr := func(s string) (*connection.Info, error) {
		addr, err := snet.AddrFromString(s)
		if err != nil {
			return nil, err
		}
		return &connection.Info{
			Type: connection.SCION,
			SCIONAddr: &connection.SCIONAddr{
				RemoteAddr: addr,
			},
		}, nil
	}
	if *rootServerSCION != "" {
		if ci, err := scionFromStr(*rootServerSCION); err != nil {
			log.Warn("failed to parse SCION root server address")
		} else {
			roots = append(roots, *ci)
		}
	}
	if *fwdServerSCION != "" {
		if ci, err := scionFromStr(*rootServerSCION); err != nil {
			log.Warn("failed to parse SCION forwarding server address")
		} else {
			fwds = append(fwds, *ci)
		}
	}

	resolver = libresolve.New(roots, fwds, mode)
	q := &query.Name{
		Name:    *name,
		Context: *context,
	}
	result, err := resolver.ClientLookup(q)
	if err != nil {
		log.Error("Failed to execute query: %v", err)
	}
	for i, sec := range result.Content {
		log.Info("Printing section %d", i)
		switch sec.(type) {
		case *section.Assertion, *section.Shard, *section.Zone, *query.Name, *section.Notification,
			*section.AddrAssertion, *query.Address:
			parser := zonefile.Parser{}
			fmt.Printf("%s\n", parser.Encode(sec))
		default:
			log.Warn("Received an unexpected section type in response:", "section", sec)
		}
	}
}
