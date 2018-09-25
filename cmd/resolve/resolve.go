package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fehlmach/rains/utils/zoneFileParser"
	"github.com/golang/glog"

	"github.com/netsec-ethz/rains/internal/pkg/resolver"
	"github.com/netsec-ethz/rains/internal/pkg/rainslib"
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
	glog.Infof("Starting resolver client.")
	if *name == "" {
		glog.Fatalf("-name flag must be specified.")
	}
	var server *resolver.Server
	if *rootServer != "" {
		roots := strings.Split(*rootServer, ",")
		server = resolver.New(roots, nil, resolver.ResolutionModeRecursive, *insecureTLS)
	} else if *fwdServer != "" {
		forwarders := strings.Split(*fwdServer, ",")
		server = resolver.New(nil, forwarders, resolver.ResolutionModeForwarding, *insecureTLS)
	} else {
		glog.Fatal("At least one of -root or -fwd must be specified.")
	}
	result, err := server.Lookup(*name, *context)
	if err != nil {
		glog.Fatalf("Failed to execute query: %v", err)
	}
	for i, section := range result.Content {
		glog.Infof("Printing section %d", i)
		switch section.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection, *rainslib.QuerySection, *rainslib.NotificationSection,
			*rainslib.AddressAssertionSection, *rainslib.AddressQuerySection, *rainslib.AddressZoneSection:
			parser := zoneFileParser.Parser{}
			fmt.Printf("%s\n", parser.Encode(section))
		default:
			glog.Warningf("Received an unexpected section type in response: %T, %v", section, section)
		}
	}
}
