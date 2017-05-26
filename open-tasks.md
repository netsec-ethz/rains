# RAINS Open Tasks

- Large Tasks
	- Write Unit tests for the server (switchboad, inbox, verify, engine)
	- Write Unit tests for the cache implementations
	- Write Unit tests for the parser implementations
	- Write Integration tests
	- Have a working basic workflow from generation of zone files, publish them via rainspub,  signature verification on the server, query the server and check response via rainsdig
	- Integrate RAINS into SCION
	- Benchmark and stress test
	- non disruptive key rollover (red-black key)
	- add name (reverse) lookups
	- multiple types in one assertion (Be aware that then also the cache design must be changed)
	- performance analysis and optimizations (in the normal and attack case)
	- Token handling, including prioritization of packets and dropping in case of congestion.
	- implement CBOR parser
	- airgapping to sign elements of a zone file
	- verify whole signature chain
	- come up with heuristics when an assertion should be cached
	- Heuristic, if a server should actively fetch/push a new assertion in case of expiration.
	- Heuristic which assertion should be returned to a query if there are multiple available
	- Pretty print the output of rainsDig (add more functionality)
	- implement capability handling sent with a message
	- Heuristics how to groupe assertions into shards

- Small Tasks
	- load config from file instead of using hardcoded default
	- verify and add signature on a message
	- come up with a heuristic for splitting name and zone in a query.
	- use net.TCP as address instead of own struct inside ConnInfo struct.

