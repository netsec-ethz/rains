//The switchboard listens for incoming connections from servers or clients,
//opens connections to servers to which messages need to be sent but for which no active connection is available
//and provides the SendTo function which sends the message to the specified server.

package rainsd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
)

const (
	configPath = "config"
)

//TODO create cache of RAINS Servers to which this server has an open connection, replacement strategy when full should be configurable
//create an object with an interface (method) where we can change replacement strategies
//when the object is initialized choose as a parameter the replacement strategy. Can be done by config file or hardcoded at beginning

//TODO periodically send heartbeat to all server connections (store ConnInfo of servers in a different cache and look up writer in the active cache)

//SendTo sends the given message to the specified receiver.
func SendTo(message RainsMessage, receiver ConnInfo) {
	//TODO look up writer from active cache based on ConnInfo
	//If no connection found-> create new connection
	//send message out
	//TODO log if send was successful or not
	/*tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}*/
	server := &http.Server{}
	log.Fatal(server.ListenAndServeTLS(Config.CertificateFile, Config.PrivateKeyFile))

	conn, err := net.Dial("tcp", "golang.org:80")

}

//listens for incoming connections and calls handler
func listen() {
	http.HandleFunc("/", handler)
	connInfo := getIPAddrandPort()
	port := strconv.Itoa(int(connInfo.Port))
	log.Fatal(http.ListenAndServe(connInfo.Host.IPAddr+":"+port, nil))
}

//handler adds some server connections to the cache (depending on the configuration) and forwards the received message to the inbox
func handler(w http.ResponseWriter, r *http.Request) {
	//TODO how do we send information back after we processed the incoming message
	//suggestion: store writer in a cache and if a message for this client is comming in, we can write it back.
}

//fetches HostAddr and port number form config file on which this server is listening to
func getIPAddrandPort() ConnInfo {
	if Config.ServerIPAddr == "" || Config.ServerPort == 0 {
		log.Fatal("Server's IPAddr or port are not in config")
	}
	host := HostAddr{Config.ServerIPAddr}
	return ConnInfo{Host: host, Port: Config.ServerPort}
}

//load config and stores it into config map encoded as key,value in each line
//TODO move this function to a global place
func loadConfig() {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(file, &Config)
}
