# README

This document describes the different components of the integration test and what we are testing.

## Topology

The integration consists of three authoritative servers, 2 caching resolvers and a client sending
queries to the two caching resolvers. There is one authoritative server for the root, a TLD and a
SLD. The SLD is a subzone of the TLD. The caching resolvers start their recursive lookups at the
root and get then referred to the other authoritative servers.

## Queries
The queries the client is going to send and expected answers are stored in a file located at
'testdata/messages/messages.txt'. The query must be on a single line. The answer sections must be on
the following line(s). An empty line marks the end of the answer. Queries are represented in a
zonefile like format and answers are represented in zonefile format.

## Test

The integration test covers the following parts:

- Loading files such as config, zonefile, keys, checkpoints, certificates
- tcp connection handling and sending messages over tcp between all components
- SCION connection handling and sending messages over SCION between all components
  (To run the SCION part of the integration test, you need to have SCION installed and
  start a local topology like this, WARNING this overwrites the gen folder:
  cd $SC; PYTHONPATH=$PYTHONPATH:$SC/topology:$SC/python python/topology/generator.py -c $SC/topology/Tiny.topo
  echo  '1-ff00_0_110' > ./gen/ia
  ./supervisor/supervisor.sh reload
  ./supervisor/supervisor.sh start dispatcher
  ./supervisor/supervisor.sh start as1-ff00_0_110:*)
- recursive lookup with and without alias
- preprocessing and publishing zone information
- preloading caches of a caching resolver from checkpoint files
- a caching resolver answers with cached entries if present
- marshal and unmarshal of messages and sections
- signing sections and verifying signatures
- queries are correctly answered
- key generation, storing and loading

## Coverage
The file fullCoverageTCP.go must be present and include all paths for which we want to do coverage
measurements. Otherwise the coverage tool does not add instrumentation code to these packages.

To create coverage measurements execute the following commands:
- go test -coverprofile=coverage.out -coverpkg=../../internal/pkg/...
- go tool cover -html=coverage.out -o coverage.html
- firefox coverage.html