package integration

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

func TestFullCoverage(t *testing.T) {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, h))
	//Start authoritative Servers and publish zonefiles to them
	rootServer := startAuthServer(t, "Root", nil)
	chServer := startAuthServer(t, "ch", []connection.Info{rootServer.Addr()})
	ethzChServer := startAuthServer(t, "ethz.ch", []connection.Info{rootServer.Addr()})

	//Start client resolver
	cachingResolver, err := rainsd.New("testdata/conf/resolver.conf", "resolver")
	if err != nil {
		t.Fatalf("Was not able to create client resolver: %v", err)
	}
	cachingResolver.SetResolver(libresolve.New([]connection.Info{rootServer.Addr()}, nil,
		libresolve.Recursive, cachingResolver.Addr()))
	go cachingResolver.Start(false)
	time.Sleep(5000 * time.Millisecond)

	//Send queries to client resolver and observe the recursive lookup results.
	queries := loadQueries(t)
	answers := loadAnswers(t)
	for i, query := range queries {
		sendQuery(t, *query, cachingResolver.Addr(), answers[i])
	}

	//Shut down authoritative servers
	rootServer.Shutdown()
	chServer.Shutdown()
	ethzChServer.Shutdown()

	//Send queries to client resolver and observe the cached results.
	for i, query := range queries {
		sendQuery(t, *query, cachingResolver.Addr(), answers[i])
	}
}

func startAuthServer(t *testing.T, name string, rootServers []connection.Info) *rainsd.Server {
	server, err := rainsd.New("testdata/conf/namingServer"+name+".conf", "nameServerRoot")
	if err != nil {
		t.Fatal(fmt.Sprintf("Was not able to create %s server: ", name), err)
	}
	server.SetResolver(libresolve.New(rootServers, nil, libresolve.Recursive, server.Addr()))
	go server.Start(false)
	config, err := publisher.LoadConfig("testdata/conf/publisher" + name + ".conf")
	if err != nil {
		t.Fatal(fmt.Sprintf("Was not able to load %s publisher config: ", name), err)
	}
	pubServer := publisher.New(config)
	pubServer.Publish()
	time.Sleep(1000 * time.Millisecond)
	return server
}

func loadQueries(t *testing.T) []*query.Name {
	encoding, err := ioutil.ReadFile("testdata/messages/queries.txt")
	if err != nil {
		t.Fatal("Was not able to open queries.txt file: ", err)
	}
	zfParser := zonefile.Parser{}
	queries := zfParser.DecodeNameQueriesUnsafe(encoding)
	for _, q := range queries {
		q.Expiration = time.Now().Add(time.Hour).Unix()
	}
	return queries
}

func loadAnswers(t *testing.T) []section.WithSigForward {
	encoding, err := ioutil.ReadFile("testdata/messages/answers.txt")
	if err != nil {
		t.Fatal("Was not able to open answers.txt file: ", err)
	}
	zfParser := zonefile.Parser{}
	sections, err := zfParser.Decode(encoding)
	if err != nil {
		t.Fatal("Was not able to parse answers.txt file: ", err)
	}
	return sections
}

func sendQuery(t *testing.T, query query.Name, connInfo connection.Info, answer section.Section) {
	msg := message.Message{Token: token.New(), Content: []section.Section{&query}}
	answerMsg, err := util.SendQuery(msg, connInfo, time.Second)
	if err != nil {
		t.Fatalf("could not send query or receive answer. query=%v err=%v", msg.Content, err)
	}
	if len(answerMsg.Content) != 1 || answerMsg.Content[0] != answer {
		t.Fatalf("Answer does not match expected result. actual=%v expected=%v",
			answerMsg.Content[0], answer)
	}
}
