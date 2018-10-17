package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/generate"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

var port = 5022

//Simulation parameters: TODO allow the user to overwrite them via command line
const (
	nofRootNamingServers      = 1
	nofTLDNamingServers       = 1
	nofSLDNamingServersPerTLD = 1
	nofResolvers              = 1
	nofClients                = 1
	leafZoneSize              = 3
	zfPath                    = "zonefiles/zf_"
)

func main() {
	idToResolver := make(map[int]*rainsd.Server)
	authNames, fqdn := generate.Zones(nofTLDNamingServers, nofSLDNamingServersPerTLD, leafZoneSize, zfPath)

	for i, name := range authNames {
		path := createConfig("conf/namingServer.conf", name)
		server, err := rainsd.New(path, log.LvlDebug, fmt.Sprintf("nameServer%d", i))
		panicOnError(err)
		go server.Start(false)
		path = createPublisherConfig("conf/publisher.conf", name)
		//TODO periodically invoke publisher (before current signatures expire)
		config, err := publisher.LoadConfig(path)
		panicOnError(err)
		pubServer := publisher.New(config)
		pubServer.Publish()
	}
	for i := 0; i < nofResolvers; i++ {
		path := createConfig("conf/resolver.conf", strconv.Itoa(i))
		server, err := rainsd.New(path, log.LvlDebug, fmt.Sprintf("resolver%d", i))
		panicOnError(err)
		idToResolver[i] = server
		go server.Start(false)
		//TODO preload cache
	}
	//TODO create client to resolver mapping
	traces := generate.Traces(nil, 10, 5, fqdn, time.Now().Add(time.Second).Unix(), time.Now().Add(5*time.Second).Unix(), 0, 2)
	for i := 0; i < nofClients; i++ {
		go startClient(traces[i], idToResolver[0]) //TODO choose resolver based on mapping, not hardcoded
	}

	//Initialize caching resolvers with the correct public and private keys and root server addr (channel)
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func startClient(trace generate.Queries, server *rainsd.Server) {
	//send queries based on trace. log delay
	result := make(chan map[token.Token]int64)
	rcvChan := make(chan connection.Message, 10)
	channel := &connection.Channel{RemoteChan: rcvChan}
	channel.SetRemoteAddr(connection.ChannelAddr{ID: trace.ID})
	go clientListener(trace.ID, len(trace.Trace), rcvChan, result)
	for _, q := range trace.Trace {
		//TODO CFE add dynamic delay
		time.Sleep(time.Duration(q.SendTime - time.Now().UnixNano()))
		q.SendTime = time.Now().UnixNano()
		encoding := new(bytes.Buffer)
		err := q.Info.MarshalCBOR(borat.NewCBORWriter(encoding))
		panicOnError(err)
		server.Write(connection.Message{Msg: encoding.Bytes(), Sender: channel})
	}
	delayLog := <-result
	delaySum := int64(0) //in ms
	for _, q := range trace.Trace {
		delaySum += nanoToMilliSecond(delayLog[q.Info.Token] - q.SendTime)
	}
}

func clientListener(id string, nofQueries int, rcvChan chan connection.Message, result chan map[token.Token]int64) {
	delayLog := make(map[token.Token]int64)
	for ; nofQueries > 0; nofQueries-- {
		data := <-rcvChan
		msg := &message.Message{}
		err := msg.UnmarshalCBOR(borat.NewCBORReader(bytes.NewReader(data.Msg)))
		panicOnError(err)
		//TODO CFE add dynamic delay
		delayLog[msg.Token] = time.Now().UnixNano()
		log.Debug(id, "RcvMsg", msg, "ContentType", fmt.Sprintf("%T", msg.Content[0]))
	}
	result <- delayLog
}

func nanoToMilliSecond(in int64) int64 {
	return in / 1000000
}

func createConfig(path, authoritativeZone string) string {
	content, err := ioutil.ReadFile(path)
	panicOnError(err)
	config := strings.Replace(string(content), "Port\": 5022", fmt.Sprintf("Port\": %d", port), 1)
	config = strings.Replace(config, "zoneAuthValue", authoritativeZone, 1)
	path = strings.Replace(path, ".conf", authoritativeZone+".conf", 1)
	ioutil.WriteFile(path, []byte(config), 0600)
	return path
}

func createPublisherConfig(path, name string) string {
	content, err := ioutil.ReadFile(path)
	panicOnError(err)
	config := strings.Replace(string(content), "Port\": 5022", fmt.Sprintf("Port\": %d", port), 1)
	config = strings.Replace(config, "zonefiles/zf_", "zonefiles/zf_"+name, 1)
	config = strings.Replace(config, "keys/privateKey", "keys/privateKey"+name, 1)
	path = strings.Replace(path, ".conf", fmt.Sprintf("%d.conf", port-5022), 1)
	ioutil.WriteFile(path, []byte(config), 0600)
	port++
	return path
}
