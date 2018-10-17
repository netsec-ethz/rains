package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/generate"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

func main() {
	nofNamingServers := 2
	nofResolvers := 1
	nofClients := 5
	idToServer := make(map[int]*rainsd.Server)

	for i := 0; i < nofNamingServers; i++ {
		server, err := rainsd.New("config/namingServer.conf", log.LvlDebug, fmt.Sprintf("nameServer%d", i))
		panicOnError(err)
		idToServer[i] = server
		go server.Start(false)
	}
	for i := 0; i < nofResolvers; i++ {
		server, err := rainsd.New("config/resolver.conf", log.LvlDebug, fmt.Sprintf("resolver%d", i))
		panicOnError(err)
		idToServer[i] = server
		go server.Start(false)
	}
	for i := 0; i < nofClients; i++ {
		go startClient(generate.Queries{}, idToServer[0])
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
		delayLog[msg.Token] = time.Now().UnixNano()
		log.Debug(id, "RcvMsg", msg, "ContentType", fmt.Sprintf("%T", msg.Content[0]))
	}
	result <- delayLog
}

func nanoToMilliSecond(in int64) int64 {
	return in / 1000000
}
