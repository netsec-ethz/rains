package main

import "github.com/netsec-ethz/rains/internal/pkg/rainsd"

func main() {
	nofNamingServers := 2
	nofResolvers := 1
	nofClients := 5
	idToServer := make(map[int]*rainsd.Server)

	for i := 0; i < nofNamingServers; i++ {
		server, err := rainsd.New("config/namingServer.conf", log.LvlDebug, i)
		idToServer[i] = server
		go server.Start(false)
	}
	for i := 0; i < nofResolvers; i++ {
		server, err := rainsd.New("config/resolver.conf", log.LvlDebug, i)
		idToServer[i] = server
		go server.Start(false)
	}
	for i := 0; i < nofClients; i++ {
		go startClient()
	}

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

func startClient() {
	//send queries based on trace. log delay
}
