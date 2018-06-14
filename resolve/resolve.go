package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/netsec-ethz/rains/libresolve"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"

	log "github.com/inconshreveable/log15"
)

var (
	name          = flag.String("name", "", "Name to query the server for.")
	context       = flag.String("context", ".", "Context in which to query.")
	rootResolvers = flag.String("root", "", "Comma separated list of root resolvers to query.")
	fwdResolvers  = flag.String("fwd", "", "Comma separated list of recursive resolvers to query.")
	insecureTLS   = flag.Bool("insecureTLS", false, "Whether to validate the TLS certificate of the server.")
)

func main() {
	flag.Parse()
	log.Info("Starting resolver client.")
	if *name == "" {
		log.Error("-name flag must be specified.")
		return
	}
	var resolver *libresolve.Resolver
	if *rootResolvers != "" {
		roots := strings.Split(*rootResolvers, ",")
		resolver = libresolve.New(roots, nil, libresolve.ResolutionModeRecursive, *insecureTLS)
	} else if *fwdResolvers != "" {
		forwarders := strings.Split(*fwdResolvers, ",")
		resolver = libresolve.New(nil, forwarders, libresolve.ResolutionModeForwarding, *insecureTLS)
	} else {
		log.Error("At least one of -root or -fwd must be specified.")
		return
	}
	result, err := resolver.Lookup(*name, *context)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to execute query: %v", err))
	}
	for i, section := range result.Content {
		log.Info(fmt.Sprintf("Printing section %d", i))
		switch section.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection, *rainslib.QuerySection, *rainslib.NotificationSection,
			*rainslib.AddressAssertionSection, *rainslib.AddressQuerySection, *rainslib.AddressZoneSection:
			parser := zoneFileParser.Parser{}
			fmt.Printf("%s\n", parser.Encode(section))
		default:
			log.Warn(fmt.Sprintf("Received an unexpected section type in response: %T, %v", section, section))
		}
	}
}
