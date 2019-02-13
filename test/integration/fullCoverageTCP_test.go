package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
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
	//Generate self signed root key
	os.Mkdir("testdata/keys/root", os.ModePerm)
	err := keyManager.GenerateKey("testdata/keys/root", "root", "",
		algorithmTypes.Ed25519.String(), "", 1)
	if err != nil {
		t.Fatalf("Was not able to generate root key pair: %v", err)
	}
	if err := keyManager.SelfSignedDelegation("testdata/keys/root/root",
		"testdata/keys/selfSignedRootDelegationAssertion.gob", "", ".", ".", 24*time.Hour); err != nil {
		t.Fatalf("Was not able to self sign root key pair: %v", err)
	}

	//Start authoritative Servers and publish zonefiles to them
	rootServer := startAuthServer(t, "Root", nil)
	chServer := startAuthServer(t, "ch", []net.Addr{rootServer.Addr()})
	ethzChServer := startAuthServer(t, "ethz.ch", []net.Addr{rootServer.Addr()})
	log.Info("all authoritative servers successfully started")
	//Start client resolver
	conf, err := rainsd.LoadConfig("testdata/conf/resolver.conf")
	if err != nil {
		t.Fatalf("Was not able to load resolver config: %v", err)
	}
	cachingResolver, err := rainsd.New(conf, "resolver")
	if err != nil {
		t.Fatalf("Was not able to create client resolver: %v", err)
	}
	resolver, err := libresolve.New([]net.Addr{rootServer.Addr()}, nil, rootServer.Config().RootZonePublicKeyPath,
		libresolve.Recursive, cachingResolver.Addr(), 1000, rootServer.Config().MaxCacheValidity, 50)
	if err != nil {
		panic(err.Error())
	}
	cachingResolver.SetResolver(resolver)
	go cachingResolver.Start(false)
	time.Sleep(1000 * time.Millisecond)
	log.Info("caching server successfully started")

	//Send queries to client resolver and observe the recursive lookup results.
	qs, as := loadQueriesAndAnswers(t)
	queries := decodeQueries([]byte(qs))
	log.Info("successfully decoded queries", "queries", queries, "length", len(queries))
	answers := decodeAnswers([]byte(as), t)
	log.Info("successfully decoded answers", "answers", answers)
	log.Info("begin sending queries which require recursive lookup")
	for i, query := range queries {
		sendQueryVerifyResponse(t, *query, cachingResolver.Addr(), answers[i])
	}
	log.Warn("Done sending queries for recursive lookups")

	//Shut down authoritative servers
	rootServer.Shutdown()
	chServer.Shutdown()
	ethzChServer.Shutdown()
	time.Sleep(500 * time.Millisecond)
	log.Info("begin sending queries which should be cached by recursive lookup")
	for i, query := range queries {
		sendQueryVerifyResponse(t, *query, cachingResolver.Addr(), answers[i])
	}
	log.Warn("Done sending queries for cached entries from a recursive lookup")

	//Restart caching resolver from checkpoint
	time.Sleep(1000 * time.Millisecond) //make sure that caches are checkpointed
	cachingResolver.Shutdown()
	conf, err = rainsd.LoadConfig("testdata/conf/resolver2.conf")
	if err != nil {
		t.Fatalf("Was not able to load resolver2 config: %v", err)
	}
	cachingResolver2, err := rainsd.New(conf, "resolver2")
	if err != nil {
		t.Fatalf("Was not able to create client resolver: %v", err)
	}
	go cachingResolver2.Start(false)
	time.Sleep(500 * time.Millisecond)
	log.Info("caching server successfully started")
	log.Info("begin sending queries which should be cached by pre load")
	for i, query := range queries {
		sendQueryVerifyResponse(t, *query, cachingResolver2.Addr(), answers[i])
	}
	log.Warn("Done sending queries for cached entries that are preloaded")
	cachingResolver2.Shutdown()
}

func TestFullCoverageCLITools(t *testing.T) {
	// Same integration test as TestFullCoverage, using the CLI tools instead

	// build the CLI tools
	tool_dir, err := ioutil.TempDir("", "rains_tools")
	if err != nil {
		t.Fatalf("Error during tmp dir creation: %v", err)
	} else {
		log.Info("Created tmp dir", "path", tool_dir)
	}

	for _, tool := range []string{"rainsd", "zonepub", "rdig"} {
		cmd := exec.Command("/bin/bash", "-c",
			fmt.Sprintf("go build -o %s/%s -v "+
				"$GOPATH/src/github.com/netsec-ethz/rains/cmd/%[2]s/%[2]s.go",
				tool_dir, tool))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Error during build of %v: %v", tool, err)
		}
	}

	// Start the name servers and publish the zone information
	var commands []*exec.Cmd
	defer func() {
		// cleanup after test
		for _, cmd := range commands {
			if err := cmd.Process.Kill(); err != nil {
				fmt.Printf("Failed to kill process: %v", err)
			}
		}

		if err := os.RemoveAll(tool_dir); err != nil {
			fmt.Printf("Error while removing %v: %v", tool_dir, err)
		}
	}()
	root_config, err := rainsd.LoadConfig("testdata/conf/namingServerRoot.conf")
	if err != nil {
		t.Fatalf("Was not able to load namingServerRoot config: %v", err)
	}
	root_ip_addr, err := net.ResolveTCPAddr("", root_config.ServerAddress.Addr.String())
	if err != nil {
		t.Fatalf("Was not able to load ServerAddress from namingServerRoot config: %v", err)
	}
	root_ip := root_ip_addr.IP.String()
	root_port := strconv.Itoa(root_ip_addr.Port)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf("%s/rainsd "+
			"./testdata/conf/namingServerRoot.conf --id nameServerRoot", tool_dir))
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
	}
	commands = append(commands, cmd)
	time.Sleep(250 * time.Millisecond)

	cmd = exec.Command("/bin/bash", "-c", fmt.Sprintf("%s/zonepub "+
		"./testdata/conf/publisherRoot.conf", tool_dir))
	if err := cmd.Run(); err != nil {
		t.Fatalf("Error during zonepub %v: %v", "zonepub", err)
	}
	time.Sleep(1000 * time.Millisecond)

	for _, zone := range []string{"ch", "ethz.ch"} {
		cmd = exec.Command("/bin/bash", "-c", fmt.Sprintf("%s/rainsd "+
			"./testdata/conf/namingServer%[2]s.conf "+
			"--rootServerAddress %s:%s --id nameServer%[2]s", tool_dir, zone, root_ip,
			root_port))
		if err := cmd.Start(); err != nil {
			t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
		}
		commands = append(commands, cmd)
		time.Sleep(250 * time.Millisecond)

		cmd = exec.Command("/bin/bash", "-c", fmt.Sprintf("%s/zonepub "+
			"./testdata/conf/publisher%s.conf", tool_dir, zone))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Error during zonepub %v: %v", "zonepub", err)
		}
		time.Sleep(1000 * time.Millisecond)
	}

	// Start a resolver
	resolver_config, err := rainsd.LoadConfig("testdata/conf/resolver.conf")
	if err != nil {
		t.Fatalf("Was not able to load resolver config: %v", err)
	}
	resolver_ip_addr, err := net.ResolveTCPAddr("", resolver_config.ServerAddress.Addr.String())
	if err != nil {
		t.Fatalf("Was not able to load ServerAddress from resolver config: %v", err)
	}
	resolver_ip := resolver_ip_addr.IP.String()
	resolver_port := strconv.Itoa(resolver_ip_addr.Port)
	cmd = exec.Command("/bin/bash", "-c", fmt.Sprintf("%s/rainsd "+
		"./testdata/conf/resolver.conf "+
		"--rootServerAddress %s:%s --id resolver", tool_dir, root_ip, root_port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
	}
	commands = append(commands, cmd)
	time.Sleep(1000 * time.Millisecond)

	// Load queries with expected answer
	qs, as := loadQueriesAndAnswers(t)
	queries := decodeQueries([]byte(qs))
	log.Info("successfully decoded queries", "queries", queries, "length", len(queries))
	answers := decodeAnswers([]byte(as), t)
	log.Info("successfully decoded answers", "answers", answers)

	for i, rquery := range queries {
		// Run a query against the resolver
		qtype := rquery.Types[0].CLIString()
		if err != nil {
			t.Fatalf("Error during rdig %v: %v", "type", err)
		}
		log.Info("Running:", "rdig query", fmt.Sprintf("%s/rdig -p %s @%s %s %s",
			tool_dir, resolver_port, resolver_ip, rquery.Name, qtype))
		cmd = exec.Command("/bin/bash", "-c", fmt.Sprintf("%s/rdig -p %s @%s %s %s",
			tool_dir, resolver_port, resolver_ip, rquery.Name, qtype))
		cmdOut, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatalf("Error during rdig %v: %v", "rdig", err)
		}
		stdOutput, _ := ioutil.ReadAll(cmdOut)
		log.Info(fmt.Sprintf("rdig out:\n%v", string(stdOutput)))
		cmd.Wait()

		rdig_answer := string(stdOutput)
		sig_part := regexp.MustCompile(` \( :sig: :.*\n`)
		rdig_answer = sig_part.ReplaceAllString(rdig_answer, "")
		rdig_answer = strings.TrimSpace(rdig_answer)
		expected_ans := strings.TrimSpace(
			fmt.Sprint(zonefile.IO{}.Encode([]section.Section{answers[i]})))
		if rdig_answer != expected_ans {
			t.Fatalf("Expected %v\nGot: %v",
				expected_ans,
				rdig_answer)
		}
	}
}

func startAuthServer(t *testing.T, name string, rootServers []net.Addr) *rainsd.Server {
	conf, err := rainsd.LoadConfig("testdata/conf/namingServer" + name + ".conf")
	if err != nil {
		t.Fatalf("Was not able to load namingServer%s config: %v", name, err)
	}
	server, err := rainsd.New(conf, "nameServer"+name)
	if err != nil {
		t.Fatal(fmt.Sprintf("Was not able to create %s server: ", name), err)
	}
	resolver, err := libresolve.New(rootServers, nil, server.Config().RootZonePublicKeyPath,
		libresolve.Recursive, server.Addr(), 1000, server.Config().MaxCacheValidity, 50)
	if err != nil {
		panic(err.Error())
	}
	server.SetResolver(resolver)
	go server.Start(false)
	time.Sleep(250 * time.Millisecond)
	config, err := publisher.LoadConfig("testdata/conf/publisher" + name + ".conf")
	if err != nil {
		t.Fatal(fmt.Sprintf("Was not able to load %s publisher config: ", name), err)
	}
	pubServer := publisher.New(config)
	if err := pubServer.Publish(); err != nil {
		t.Fatalf("%s publisher error: %v", name, err)
	}
	time.Sleep(1000 * time.Millisecond)
	return server
}

func loadQueriesAndAnswers(t *testing.T) (string, string) {
	var answers, queries []string
	input, err := ioutil.ReadFile("testdata/messages/messages.txt")
	if err != nil {
		t.Fatal("Was not able to open messages.txt file: ", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(input))
	for scanner.Scan() {
		queries = append(queries, scanner.Text())
		for scanner.Scan() {
			if scanner.Text() == "" {
				break
			}
			answers = append(answers, scanner.Text())
		}
	}
	return strings.Join(queries, "\n"), strings.Join(answers, "\n")
}

func decodeQueries(input []byte) []*query.Name {
	zfParser := zonefile.IO{}
	queries := zfParser.DecodeNameQueriesUnsafe(input)
	for _, q := range queries {
		q.Expiration = time.Now().Add(time.Hour).Unix()
	}
	return queries
}

func decodeAnswers(input []byte, t *testing.T) []section.WithSigForward {
	zfParser := zonefile.IO{}
	sections, err := zfParser.Decode(input)
	if err != nil {
		t.Fatal("Was not able to parse answers.txt file: ", err)
	}
	return sections
}

func sendQueryVerifyResponse(t *testing.T, query query.Name, connInfo net.Addr,
	answer section.Section) {
	msg := message.Message{Token: token.New(), Content: []section.Section{&query}}
	log.Warn("Integration test sends query", "msg", msg)
	answerMsg, err := util.SendQuery(msg, connInfo, time.Second)
	if err != nil {
		t.Fatalf("could not send query or receive answer. query=%v err=%v",
			msg.Content, err)
	}
	if len(answerMsg.Content) != 1 {
		t.Fatalf("Got not exactly one answer for the query. msg=%v", answerMsg)
	}
	correctAnswer := false
	switch s := answerMsg.Content[0].(type) {
	case *section.Assertion:
		if a, ok := answer.(*section.Assertion); ok {
			correctAnswer = s.CompareTo(a) == 0
		}
	case *section.Shard:
		if a, ok := answer.(*section.Shard); ok {
			correctAnswer = s.CompareTo(a) == 0
		}
	case *section.Pshard:
		if a, ok := answer.(*section.Pshard); ok {
			correctAnswer = s.CompareTo(a) == 0
		}
	case *section.Zone:
		if a, ok := answer.(*section.Zone); ok {
			correctAnswer = s.CompareTo(a) == 0
		}
	default:
		t.Fatalf("Not yet implemented! So far only assertion, shard, "+
			"pshard and zones are supported. section=%v", s)
	}
	if !correctAnswer {
		t.Fatalf("Answer does not match expected result. actual=%v expected=%v",
			answerMsg.Content[0], answer)
	}
}
