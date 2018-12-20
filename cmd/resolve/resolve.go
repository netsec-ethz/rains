package main

import (
	"flag"

	log "github.com/inconshreveable/log15"
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
	/*var server *resolver.Server
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
	for i, sec := range result.Content {
		log.Info("Printing section %d", i)
		switch sec.(type) {
		case *section.Assertion, *section.Shard, *section.Zone, *query.Name, *section.Notification,
			*section.AddrAssertion, *query.Address:
			parser := zonefile.IO{}
			fmt.Printf("%s\n", parser.Encode(sec))
		default:
			log.Warn("Received an unexpected section type in response:", "section", sec)
		}
	}*/
}
