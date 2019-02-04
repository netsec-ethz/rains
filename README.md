# RAINS, Another Internet Naming Service

This repository contains a reference implementation of a RAINS server,
supporting authority, intermediary, and query service, as well as associated
tools for managing the server. It has the following executables:

- `rainsd`: A configurable RAINS server
- `rdig`: A command-line tool for querying RAINS servers
- `zonepub`: A command-line tool for a naming authority to publish information
  about its zone(s) to its authoritative RAINS servers
- `keyManager`: A command-line tool for a naming authority to manage its 
  key pairs

In addition to this there is a resolver in `libresolve` which either forwards
a query to a RAINS server to resolve it or performs a recursive lookup itself
on the callers behalf before sending the received answer back to the caller.


## Understanding RAINS

The RAINS implementation is based on the RAINS protocol specified in the
[Internet draft](https://tools.ietf.org/html/draft-trammell-rains-protocol-05).
The different components necessary to run
a RAINS infrastructure are described [here](docs/components-overview.md).
The design of this RAINS server is explained [here](docs/rains-server-design.md) and 
the [cache folder](docs/cache-design) contains design decisions for all caches. The
zonefile format, designed to be conveniently readable by a human, is defined in 
backus normal form [here](docs/zonefile-format.md). Each command line tool has a help
page which explains all commands and flags that are supported.

## Installing and using RAINS

### On your machine

The following installation steps were tested for TODO define os and version

1. Install and setup go development environment [TODO source]
2. Download the repo e.g. `go get github.com/netsec-ethz/rains`
3. Download the scion repo according to [TODO source]
4. TODO necessary? Build all executables by calling make
5. Use the binaries created in the cmd folder

### In scion lab

TODO

## Issues and Test coverage

The RAINS server and tools are under active development. An up to date
list of issues and bugs can be found [here](https://github.com/netsec-ethz/rains/issues/).

The server and all tools are tested using unit and integration tests.
A description of the integration test can be found in the [readme](test/integration/README.md)
To inspect the test coverage of all unit tests together with the integration test,
perform the following steps:
1. go test -coverprofile=coverage.out -coverpkg=./internal/pkg/... ./...
2. go tool cover -html=coverage.out -o coverage.html
3. firefox coverage.html
