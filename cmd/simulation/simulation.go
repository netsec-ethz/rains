package main

func main() {
	//Questions: simplify server's cache with hashmap? how to handle negative names?

	//Generate zonefiles
	//Generate Traces
	//Generate Mapping from IP to channel
	//Initialize and start authoritative server and load zonefile.
	//Initialize caching resolvers with the correct public and private keys and root server addr (channel)
	//Optional: load some values into the caching resolver's cache
	//Start caching resolver
	//Start clients with trace => (start a go routine that issues a new go routine that sends the query
	//in the client's name and tracks how long it takes to get an answer.)
}
