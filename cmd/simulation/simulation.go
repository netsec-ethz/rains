package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/generate"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/resolver"
	"github.com/netsec-ethz/rains/internal/pkg/simulation"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

func main() {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlError, h))
	conf := simulation.Example
	idToResolver := make(map[int]*rainsd.Server)
	authNames, globalNames, localNames, zoneIPToContinent, zoneIPToTLD, tldIndexToContinent := generate.Zones(simulation.Example)
	ipToServer := make(map[string]func(connection.Message))
	delay := &generate.Delay{
		ZoneIPToContinent: zoneIPToContinent,
		ZoneIPToTLD:       zoneIPToTLD,
		RootIPAddr:        conf.RootIPAddr,
	}
	port := conf.StartPort
	//AuthNames: names must be sorted by their hierarchy level. All names that are higher up in the
	//hierarchy must come prior to itself.
	for i, name := range authNames {
		path := createConfig("conf/namingServer.conf", name.Name, conf, port)
		server, err := rainsd.New(path, fmt.Sprintf("nameServer%d", i))
		panicOnError(err)
		recursor := resolver.New(fmt.Sprintf("-nameServer%d", i), server.Write, conf.RootIPAddr,
			ipToServer, zoneIPToContinent[name.IPAddr], zoneIPToTLD[name.IPAddr], delay) //It is ok to have an incomplete ipToServer map as only servers up to the root are necessary to get the delegations.
		go recursor.Start()
		server.SetRecursiveResolver(recursor.Write)
		ipToServer[name.IPAddr] = server.Write
		go server.Start(false)
		path = createPublisherConfig("conf/publisher.conf", name.Name, conf, port)
		//TODO periodically invoke publisher (before current signatures expire)
		time.Sleep(100 * time.Millisecond) //wait for the server to listen on connection
		config, err := publisher.LoadConfig(path)
		panicOnError(err)
		pubServer := publisher.New(config)
		pubServer.Publish()
		port++
	}

	clientToResolver := make(map[string]simulation.ClientInfo)
	clientCounter := 0
	for i := len(authNames); i < len(authNames)+conf.RootZone.Size; i++ { //Currently there is one caching resolver per country
		path := createConfig("conf/resolver.conf", strconv.Itoa(i), conf, port)
		port++
		server, err := rainsd.New(path, fmt.Sprintf("resolver%d", i))
		panicOnError(err)
		recursor := resolver.New(fmt.Sprintf("-resolver%d", i), server.Write, conf.RootIPAddr,
			ipToServer, tldIndexToContinent[i-len(authNames)], i-len(authNames), delay)
		go recursor.Start()
		server.SetRecursiveResolver(recursor.Write)
		idToResolver[i] = server
		go server.Start(false)
		for k := 0; k < len(localNames[i-len(authNames)])*conf.ClientsPerTLDName; k++ {
			clientToResolver[strconv.Itoa(clientCounter)] = simulation.ClientInfo{strconv.Itoa(i), i - len(authNames)}
			clientCounter++
		}
		//TODO preload cache
	}
	time.Sleep(time.Second)
	rand.Shuffle(len(globalNames), func(i, j int) { globalNames[i], globalNames[j] = globalNames[j], globalNames[i] })
	conf.Start = time.Now().Add(time.Second).UnixNano()
	conf.End = time.Now().Add(5 * time.Second).UnixNano()
	traces := generate.Traces(clientToResolver, globalNames, localNames, conf)
	log.Error("Queries", "", traces[0].Trace)
	for i := 0; i < conf.RootZone.Size; i++ {
		go startClient(traces[i], idToResolver[len(authNames)], conf) //TODO choose resolver based on mapping, not hardcoded
	}
	time.Sleep(time.Hour)
	//Initialize caching resolvers with the correct public and private keys and root server addr (channel)
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func startClient(trace simulation.Queries, server *rainsd.Server, conf simulation.Config) {
	//send queries based on trace. log delay
	result := make(chan map[token.Token]int64)
	rcvChan := make(chan connection.Message, 10)
	channel := &connection.Channel{RemoteChan: rcvChan}
	channel.SetRemoteAddr(connection.ChannelAddr{ID: trace.ID})
	go clientListener(trace.ID, len(trace.Trace[:]), rcvChan, result) //FIXME CFE process all queries
	for _, q := range trace.Trace[:] {                                //FIXME CFE process all queries
		q.SendTime = time.Now().UnixNano()
		time.Sleep(time.Duration(q.SendTime - time.Now().UnixNano() + conf.ClientResolverDelay.Nanoseconds()))
		encoding := new(bytes.Buffer)
		err := q.Info.MarshalCBOR(borat.NewCBORWriter(encoding))
		panicOnError(err)
		server.Write(connection.Message{Msg: encoding.Bytes(), Sender: channel})
	}
	delayLog := <-result
	delaySum := int64(0)               //in ms
	for _, q := range trace.Trace[:] { //FIXME CFE process all queries
		delaySum += nanoToMilliSecond(delayLog[q.Info.Token] - q.SendTime + conf.ClientResolverDelay.Nanoseconds())
	}
	log.Info("Delay sum", "Milliseconds", delaySum)
	zipf := rand.NewZipf(rand.New(rand.NewSource(0)), 1.03, 1, 5)
	counter := make([]int, 6)
	for i := 0; i < 1000; i++ {
		counter[int(zipf.Uint64())]++
	}
	log.Error("", "", counter)
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

func createConfig(path, authoritativeZone string, conf simulation.Config, port int) string {
	content, err := ioutil.ReadFile(path)
	panicOnError(err)
	path = strings.Replace(path, ".conf", authoritativeZone+".conf", 1)
	config := strings.Replace(string(content), "PortValue", strconv.Itoa(port), 1)
	if authoritativeZone == "Root" {
		authoritativeZone = "."
	}
	config = strings.Replace(config, "zoneAuthValue", authoritativeZone, 1)
	config = strings.Replace(config, "RootZonePublicKeyPathValue", conf.Paths.RootDelegAssertionFilePath, 1)
	ioutil.WriteFile(path, []byte(config), 0600)
	return path
}

func createPublisherConfig(path, name string, conf simulation.Config, port int) string {
	content, err := ioutil.ReadFile(path)
	panicOnError(err)
	config := strings.Replace(string(content), "PortValue", strconv.Itoa(port), 1)
	config = strings.Replace(config, "ZonefilePathValue", conf.Paths.ZonefilePath+name, 1)
	config = strings.Replace(config, "PrivateKeyPathValue", conf.Paths.KeysPath+conf.Paths.PrivateKeyFileNamePrefix+name, 1)
	config = strings.Replace(config, "SigValidSinceValue", fmt.Sprintf("%d", time.Now().Unix()), 1)
	config = strings.Replace(config, "SigValidUntilValue", fmt.Sprintf("%d", time.Now().Add(7*24*time.Hour).Unix()), 1)
	path = strings.Replace(path, ".conf", fmt.Sprintf("%d.conf", port-conf.StartPort), 1)
	ioutil.WriteFile(path, []byte(config), 0600)
	return path
}
