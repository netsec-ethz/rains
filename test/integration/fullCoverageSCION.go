package integration

import (
	"net"

	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

/*
 * This file must be present and include all paths for which we want to do coverage measurements.
 * Otherwise the coverage tool does not add instrumentation code to these packages.
 */

func AddCoverageInstrumentationSCION() {
	rainsd.New(rainsd.Config{}, "")
	publisher.New(publisher.Config{})
	libresolve.New(nil, nil, "", libresolve.Recursive, &net.TCPAddr{}, 1000, util.MaxCacheValidity{}, 50)
}
