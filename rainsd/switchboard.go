//The switchboard listens for incoming connections from servers or clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	config = "config"
)

//HostAddr contains a value which uniquely identifies a host (Rains Server or Client)
type HostAddr struct {
	IPAddr string
}

//ConnInfo contains all necessary information to uniquely identify a connection
type ConnInfo struct {
	Host HostAddr
	Port string
}

//CBORMessage encodes a message as a Concise Binary Object Representation (CBOR)
type CBORMessage []byte

//TODO create cache of RAINS Servers to which this server has an open connection, replacement strategy when full should be configurable
//create an object with an interface (method) where we can change replacement strategies
//when the object is initialized choose as a parameter the replacement strategy. Can be done by config file or hardcoded at beginning

//TODO periodically send heartbeat to all server connections (store ConnInfo of servers in a different cache and look up writer in the active cache)

//SendTo sends the given message to the specified receiver.
func SendTo(message CBORMessage, receiver ConnInfo) {
	//TODO look up writer from active cache based on ConnInfo
	//If no connection found-> create new connection
	//send message out
	//TODO log if send was successful or not
}

//listens for incoming connections and calls handler
func listen() {
	http.HandleFunc("/", handler)
	conn := getIPAddrandPort()
	log.Fatal(http.ListenAndServe(conn.Host.IPAddr+":"+conn.Port, nil))
}

//handler adds some server connections to the cache (depending on the configuration) and forwards the received message to the inbox
func handler(w http.ResponseWriter, r *http.Request) {
	//TODO how do we send information back after we processed the incoming message
	//suggestion: store writer in a cache and if a message for this client is comming in, we can write it back.
}

//fetches HostAddr and port number form config file on which this server is listening to
func getIPAddrandPort() ConnInfo {
	addr, ok := configs["IPAddr"]
	if !ok {
		log.Fatal("IPAddr not in config")
	}
	port, ok := configs["port"]
	if !ok {
		log.Fatal("port not in config")
	}
	host := HostAddr{IPAddr: addr}
	return ConnInfo{Host: host, Port: port}
}

var configs map[string]string

//load config and stores it into config map encoded as key,value in each line
func loadConfig() {
	file, err := ioutil.ReadFile(config)
	if err != nil {
		log.Fatal(err)
	}
	configs = make(map[string]string)
	for _, line := range strings.Split(string(file), "\n") {
		conf := strings.Split(line, ",")
		configs[conf[0]] = conf[1]
	}
}
