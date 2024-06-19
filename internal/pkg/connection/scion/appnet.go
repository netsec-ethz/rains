// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package connection/scion provides a simplified and functionally extended wrapper interface to the
scionproto/scion package snet.

NOTE: functions here are taken from github.com/netsec-ethz/scion-apps/pkg/pan

# SCION daemon connections

The sciond socket is assumed to be at default location, but this can
be overridden using environment variables:

	SCION_DAEMON_ADDRESS: 127.0.0.1:30255

This is convenient for the normal use case of running the endhost stack for a
single SCION AS. When running multiple local ASes, e.g. during development, the
address of the sciond corresponding to the desired AS needs to be specified in
the SCION_DAEMON_ADDRESS environment variable.

# Wildcard IP Addresses (note that this remark might be obsolete)

snet does not currently support binding to wildcard addresses. This will hopefully be
added soon-ish, but in the meantime, this package emulates this functionality.
There is one restriction, that applies to hosts with multiple IP addresses in the AS:
the behaviour will be that of binding to one specific local IP address, which means that
the application will not be reachable using any of the other IP addresses.
Traffic sent will always appear to originate from this specific IP address,
even if that's not the correct route to a destination in the local AS.

This restriction will very likely not cause any issues, as a fairly contrived
network setup would be required. Also, sciond has a similar restriction (binds
to one specific IP address).
*/
package scion

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
)

// hostContext contains the information needed to connect to the host's local SCION stack,
// i.e. the connection to sciond.
type hostContext struct {
	IA            addr.IA
	Sciond        daemon.Connector
	HostInLocalAS net.IP
}

const (
	initTimeout = 1 * time.Second
)

var (
	singletonHostContext hostContext
	initOnce             sync.Once
)

// Host initializes and returns the singleton hostContext.
func Host() *hostContext {
	initOnce.Do(mustInitHostContext)
	return &singletonHostContext
}

// DialAddr connects to the address (on the SCION/UDP network).
//
// If no path is specified in raddr, DialAddr will choose the first available path.
// This path is never updated during the lifetime of the conn. This does not
// support long lived connections well, as the path *will* expire.
// This is all that snet currently provides, we'll need to add a layer on top
// that updates the paths in case they expire or are revoked.
func DialAddr(raddr *snet.UDPAddr) (*snet.Conn, error) {
	if raddr.Path == nil {
		err := SetDefaultPath(raddr)
		if err != nil {
			return nil, err
		}
	}

	// Find our local address.
	localIP, err := resolveLocal(raddr)
	if err != nil {
		return nil, err
	}
	laddr := &net.UDPAddr{IP: localIP}

	// New network every time (inexpensive).
	sn := snet.SCIONNetwork{
		Topology:    Host().Sciond,
		SCMPHandler: snet.DefaultSCMPHandler{},
	}
	return sn.Dial(context.TODO(), "udp", laddr, raddr)
}

// Listen acts like net.ListenUDP in a SCION network.
// The listen address or parts of it may be nil or unspecified, signifying to
// listen on a wildcard address.
//
// See note on wildcard addresses in the package documentation.
func Listen(listen *net.UDPAddr) (*snet.Conn, error) {
	if listen == nil {
		listen = &net.UDPAddr{}
	}
	if listen.IP == nil || listen.IP.IsUnspecified() {
		localIP, err := defaultLocalIP()
		if err != nil {
			return nil, err
		}
		listen = &net.UDPAddr{IP: localIP, Port: listen.Port, Zone: listen.Zone}
	}

	// New network every time (inexpensive).
	sn := snet.SCIONNetwork{
		Topology:    Host().Sciond,
		SCMPHandler: snet.DefaultSCMPHandler{},
	}
	integrationEnv, _ := os.LookupEnv("SCION_GO_INTEGRATION")
	if integrationEnv == "1" || integrationEnv == "true" || integrationEnv == "TRUE" {
		fmt.Printf("Listening ia=:%v\n", Host().IA)
	}
	return sn.Listen(context.TODO(), "udp", listen)
}

func mustInitHostContext() {
	hostCtx, err := initHostContext()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing SCION host context: %v\n", err)
		os.Exit(1)
	}
	singletonHostContext = hostCtx
}

func initHostContext() (hostContext, error) {
	ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
	defer cancel()
	sciondConn, err := findSciond(ctx)
	if err != nil {
		return hostContext{}, err
	}
	localIA, err := sciondConn.LocalIA(ctx)
	if err != nil {
		return hostContext{}, err
	}
	hostInLocalAS, err := findAnyHostInLocalAS(ctx, sciondConn)
	if err != nil {
		return hostContext{}, err
	}
	return hostContext{
		IA:            localIA,
		Sciond:        sciondConn,
		HostInLocalAS: hostInLocalAS,
	}, nil
}

func findSciond(ctx context.Context) (daemon.Connector, error) {
	address, ok := os.LookupEnv("SCION_DAEMON_ADDRESS")
	if !ok {
		address = daemon.DefaultAPIAddress
	}
	sciondConn, err := daemon.NewService(address).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to SCIOND at %s "+
			"(override with SCION_DAEMON_ADDRESS): %w", address, err)
	}
	return sciondConn, nil
}

// findAnyHostInLocalAS returns the IP address of some (infrastructure) host in the local AS.
func findAnyHostInLocalAS(ctx context.Context, sciondConn daemon.Connector) (net.IP, error) {
	addr, err := daemon.TopoQuerier{Connector: sciondConn}.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

// resolveLocal returns the source IP address for traffic to raddr. If
// raddr.NextHop is set, it's used to determine the local IP address.
// Otherwise, the default local IP address is returned.
//
// The purpose of this function is to workaround not being able to bind to
// wildcard addresses in snet.
// See note on wildcard addresses in the package documentation.
func resolveLocal(raddr *snet.UDPAddr) (net.IP, error) {
	if raddr.NextHop != nil {
		nextHop := raddr.NextHop.IP
		return addrutil.ResolveLocal(nextHop)
	}
	return defaultLocalIP()
}

// defaultLocalIP returns _a_ IP of this host in the local AS.
//
// The purpose of this function is to workaround not being able to bind to
// wildcard addresses in snet.
// See note on wildcard addresses in the package documentation.
func defaultLocalIP() (net.IP, error) {
	return addrutil.ResolveLocal(Host().HostInLocalAS)
}

func queryPaths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	flags := daemon.PathReqFlags{Refresh: false, Hidden: false}
	return Host().Sciond.Paths(ctx, addr.IA(dst), 0, flags)
}
