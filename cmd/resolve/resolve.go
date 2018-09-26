package main

import (
	"flag"
	"fmt"
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/resolver"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

var (
	name        = flag.String("name", "", "Name to query the server for.")
	context     = flag.String("context", ".", "Context in which to query.")
	rootServer  = flag.String("root", "", "Comma separated list of root resolvers to query.")
	fwdServer   = flag.String("fwd", "", "Comma separated list of recursive resolvers to query.")
	insecureTLS = flag.Bool("insecureTLS", false, "Whether to validate the TLS certificate of the server.")
)

func main() {
	flag.Parse()
	log.Info("Starting resolver client.")
	if *name == "" {
		log.Error("-name flag must be specified.")
	}
	var server *resolver.Server
	if *rootServer != "" {
		roots := strings.Split(*rootServer, ",")
		server = resolver.New(roots, nil, resolver.ResolutionModeRecursive, *insecureTLS)
	} else if *fwdServer != "" {
		forwarders := strings.Split(*fwdServer, ",")
		server = resolver.New(nil, forwarders, resolver.ResolutionModeForwarding, *insecureTLS)
	} else {
		log.Error("At least one of -root or -fwd must be specified.")
	}
	result, err := server.Lookup(*name, *context)
	if err != nil {
		log.Error("Failed to execute query: %v", err)
	}
	for i, section := range result.Content {
		log.Info("Printing section %d", i)
		switch section.(type) {
		case *sections.Assertion, *sections.Shard, *sections.Zone, *sections.QueryForward, *sections.Notification,
			*sections.AddrAssertion, *sections.AddrQuery:
			parser := zonefile.Parser{}
			fmt.Printf("%s\n", parser.Encode(section))
		default:
			log.Warn("Received an unexpected section type in response:", "section", section)
		}
	}
}
