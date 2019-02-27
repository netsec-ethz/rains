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
	"strings"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"github.com/scionproto/scion/go/lib/snet"
	"syscall"
)

func TestFullCoverageSCION(t *testing.T) {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, h))
	//Generate self signed root key
	keySetup(t, "testdata/keys/root")

	//Start authoritative Servers and publish zonefiles to them
	rootServer := startSCIONAuthServer(t, "Root", nil)
	chServer := startSCIONAuthServer(t, "ch", []net.Addr{rootServer.Addr()})
	ethzChServer := startSCIONAuthServer(t, "ethz.ch", []net.Addr{rootServer.Addr()})
	log.Info("all authoritative servers successfully started")
	time.Sleep(1000 * time.Millisecond)

	//Start client resolver
	conf, err := rainsd.LoadConfig("testdata/conf/SCIONresolver.conf")
	if err != nil {
		t.Fatalf("Was not able to load resolver config: %v", err)
	}
	cachingResolver, err := rainsd.New(conf, "resolver")
	if err != nil {
		t.Fatalf("Was not able to create client resolver: %v", err)
	}
	resolver, err := libresolve.New([]net.Addr{rootServer.Addr()}, nil,
		rootServer.Config().RootZonePublicKeyPath,
		libresolve.Recursive, cachingResolver.Addr(), 1000,
		rootServer.Config().MaxCacheValidity, 50)
	if err != nil {
		panic(err.Error())
	}
	cachingResolver.SetResolver(resolver)
	go cachingResolver.Start(false, "resolver")
	time.Sleep(1000 * time.Millisecond)
	log.Info("caching server successfully started")

	//Send queries to client resolver and observe the recursive lookup results.
	qs, as := loadSCIONQueriesAndAnswers(t)
	queries := decodeQueries([]byte(qs))
	log.Info("successfully decoded queries", "queries", queries, "length", len(queries))
	answers := decodeAnswers([]byte(as), t)
	log.Info("successfully decoded answers", "answers", answers)
	log.Info("begin sending queries which require recursive lookup")
	for i, query := range queries {
		sendQueryVerifyResponse(t, *query, cachingResolver.Addr(), answers[i])
	}
	log.Warn("Done sending queries for recursive lookups")

	stopSCIONAuthServers(rootServer, chServer, ethzChServer)

	time.Sleep(500 * time.Millisecond)
	log.Info("begin sending queries which should be cached by recursive lookup")
	for i, query := range queries {
		sendQueryVerifyResponse(t, *query, cachingResolver.Addr(), answers[i])
	}
	log.Warn("Done sending queries for cached entries from a recursive lookup")

	//Restart caching resolver from checkpoint
	time.Sleep(1000 * time.Millisecond) //make sure that caches are checkpointed
	cachingResolver.Shutdown()
	conf, err = rainsd.LoadConfig("testdata/conf/SCIONresolver2.conf")
	if err != nil {
		t.Fatalf("Was not able to load resolver2 config: %v", err)
	}
	cachingResolver2, err := rainsd.New(conf, "resolver2")
	if err != nil {
		t.Fatalf("Was not able to create client resolver: %v", err)
	}
	go cachingResolver2.Start(false, "resolver2")
	time.Sleep(500 * time.Millisecond)
	log.Info("caching server successfully started")
	log.Info("begin sending queries which should be cached by pre load")
	for i, query := range queries {
		sendQueryVerifyResponse(t, *query, cachingResolver2.Addr(), answers[i])
	}
	log.Warn("Done sending queries for cached entries that are preloaded")
	cachingResolver2.Shutdown()
}

func TestFullCoverageCLIToolsSCION(t *testing.T) {
	// Same integration test as TestFullCoverage, using the CLI tools instead

	// build the CLI tools
	toolDir, err := ioutil.TempDir("", "rains_tools")
	if err != nil {
		t.Fatalf("Error during tmp dir creation: %v", err)
	} else {
		log.Info("Created tmp dir", "path", toolDir)
	}

	for _, tool := range []string{"rainsd", "zonepub", "rdig"} {
		cmd := exec.Command("/bin/bash", "-c",
			fmt.Sprintf("go build -o %s/%s -v "+
				"$GOPATH/src/github.com/netsec-ethz/rains/cmd/%[2]s/%[2]s.go",
				toolDir, tool))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Error during build of %v: %v", tool, err)
		}
	}
	log.Info("Built all tools")

	//Generate self signed root key
	keySetup(t, "testdata/keys/root")

	// Start the name servers and publish the zone information
	var commands []*exec.Cmd
	defer func() {
		// cleanup after test
		for _, cmd := range commands {
			if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
				fmt.Printf("Failed to kill process: %v", err)
			} else {
				fmt.Printf("Successfully stopped process: %v\n", cmd.Process.Pid)
			}
		}

		if err := os.RemoveAll(toolDir); err != nil {
			fmt.Printf("Error while removing %v: %v", toolDir, err)
		}
	}()
	rootConfig, err := rainsd.LoadConfig("testdata/conf/SCIONnamingServerRoot.conf")
	if err != nil {
		t.Fatalf("Was not able to load namingServerRoot config: %v", err)
	}
	rootAddr, err := snet.AddrFromString(
		strings.Replace(rootConfig.ServerAddress.Addr.String(), " (UDP)", "", 1))
	if err != nil {
		t.Fatalf("Was not able to load ServerAddress from namingServerRoot config: %v, %v",
			err, rootConfig.ServerAddress.Addr)
	}
	rootHostAddr := fmt.Sprintf("%s,[%v]", rootAddr.IA, rootAddr.Host.L3)
	rootPort := rootAddr.Host.L4.Port()
	rainsdCmd := fmt.Sprintf("%s/rainsd --sciondSock /run/shm/sciond/sd1-ff00_0_110.sock "+
		"./testdata/conf/SCIONnamingServerRoot.conf --id nameServerRootCLI 2>&1", toolDir)
	cmd := exec.Command("/bin/bash", "-c", rainsdCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	commands = append(commands, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
	}
	log.Info("Started rainsd for", "zone", "Root", "cmd", rainsdCmd)
	time.Sleep(250 * time.Millisecond)

	publishCmd := fmt.Sprintf("%s/zonepub ./testdata/conf/SCIONpublisherRoot.conf 2>&1", toolDir)
	cmd = exec.Command("/bin/bash", "-c", publishCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		t.Fatalf("Error during zonepub: %v", err)
	}
	log.Info("Published zone for", "zone", "Root", "cmd", publishCmd)
	time.Sleep(1000 * time.Millisecond)

	for _, zone := range []string{"ch", "ethz.ch"} {
		rainsdCmd = fmt.Sprintf("%s/rainsd "+
			"--sciondSock /run/shm/sciond/sd1-ff00_0_110.sock "+
			"./testdata/conf/SCIONnamingServer%[2]s.conf "+
			"--rootServerAddress %s:%d --id nameServer%[2]sCLI 2>&1", toolDir, zone,
			rootHostAddr, rootPort)
		cmd = exec.Command("/bin/bash", "-c", rainsdCmd)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		commands = append(commands, cmd)
		if err := cmd.Start(); err != nil {
			t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
		}
		log.Info("Started rainsd for", "zone", zone, "cmd", rainsdCmd)
		time.Sleep(250 * time.Millisecond)

		publishCmd = fmt.Sprintf("%s/zonepub "+
			"./testdata/conf/SCIONpublisher%s.conf 2>&1", toolDir, zone)
		cmd = exec.Command("/bin/bash", "-c", publishCmd)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Run(); err != nil {
			t.Fatalf("Error during zonepub: %v", err)
		}
		log.Info("Published zone for", "zone", zone, "cmd", publishCmd)
		time.Sleep(1000 * time.Millisecond)
	}

	// Start a resolver
	resolverConfig, err := rainsd.LoadConfig("testdata/conf/SCIONresolver.conf")
	if err != nil {
		t.Fatalf("Was not able to load resolver config: %v", err)
	}
	resolverAddr, err := snet.AddrFromString(
		strings.Replace(resolverConfig.ServerAddress.Addr.String(), " (UDP)", "", 1))
	if err != nil {
		t.Fatalf("Was not able to load ServerAddress from resolver config: %v", err)
	}
	resolverHostAddr := fmt.Sprintf("%s,[%v]", resolverAddr.IA, resolverAddr.Host.L3)
	resolverPort := resolverAddr.Host.L4.Port()
	resolverCmd := fmt.Sprintf("%s/rainsd --sciondSock /run/shm/sciond/sd1-ff00_0_110.sock "+
		"./testdata/conf/SCIONresolver.conf "+
		"--rootServerAddress %s:%d --id resolverCLI 2>&1", toolDir, rootHostAddr, rootPort)
	cmd = exec.Command("/bin/bash", "-c", resolverCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	commands = append(commands, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
	}
	log.Info("Started rainsd resolver", "cmd", resolverCmd)
	time.Sleep(5000 * time.Millisecond)

	// Load queries with expected answer
	qs, as := loadSCIONQueriesAndAnswers(t)
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
		rdigCmd := fmt.Sprintf("%s/rdig --localAS 1-ff00:0:110 "+
			"--sciondSock /run/shm/sciond/sd1-ff00_0_110.sock -p %d @%s %s %s",
			toolDir, resolverPort, resolverHostAddr, rquery.Name, qtype)
		log.Info("Running:", "rdig query", rdigCmd)
		cmd = exec.Command("/bin/bash", "-c", rdigCmd)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmdOut, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatalf("Error during rdig %v: %v", "rdig", err)
		}
		stdOutput, _ := ioutil.ReadAll(cmdOut)
		log.Info(fmt.Sprintf("rdig out:\n%v", string(stdOutput)))
		cmd.Wait()

		rdigAnswer := string(stdOutput)
		sigPart := regexp.MustCompile(` \( :sig: :.*\n`)
		rdigAnswer = sigPart.ReplaceAllString(rdigAnswer, "")
		logPart := regexp.MustCompile(`t=.*lvl=.*\n`)
		rdigAnswer = logPart.ReplaceAllString(rdigAnswer, "")
		rdigAnswer = strings.TrimSpace(rdigAnswer)
		expectedAns := strings.TrimSpace(
			fmt.Sprint(zonefile.IO{}.Encode([]section.Section{answers[i]})))
		if rdigAnswer != expectedAns {
			t.Fatalf("Expected %v\nGot: %v",
				expectedAns,
				rdigAnswer)
		}
	}
}

func startSCIONAuthServer(t *testing.T, name string, rootServers []net.Addr) *rainsd.Server {
	conf, err := rainsd.LoadConfig("testdata/conf/SCIONnamingServer" + name + ".conf")
	if err != nil {
		t.Fatalf("Was not able to load namingServer%s config: %v", name, err)
	}
	server, err := rainsd.New(conf, "nameServer"+name)
	if err != nil {
		t.Fatal(fmt.Sprintf("Was not able to create %s server: ", name), err)
	}
	resolver, err := libresolve.New(rootServers, nil, server.Config().RootZonePublicKeyPath,
		libresolve.Recursive, server.Addr(), int(time.Second), server.Config().MaxCacheValidity, 50)
	if err != nil {
		panic(err.Error())
	}
	server.SetResolver(resolver)
	go server.Start(false, "nameServer"+name)

	if len(resolver.RootNameServers) > 0 && resolver.RootNameServers[0] == nil {
		log.Error(fmt.Sprintf("Started name server %s with nil root name server: %v",
			name, resolver.RootNameServers[0]))
	}

	time.Sleep(250 * time.Millisecond)
	config, err := publisher.LoadConfig("testdata/conf/SCIONpublisher" + name + ".conf")
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

func stopSCIONAuthServers(rootServer, chServer, ethzChServer *rainsd.Server) {
	//Shut down authoritative servers
	rootServer.Shutdown()
	chServer.Shutdown()
	ethzChServer.Shutdown()
}

func loadSCIONQueriesAndAnswers(t *testing.T) (string, string) {
	var answers, queries []string
	input, err := ioutil.ReadFile("testdata/messages/SCIONmessages.txt")
	if err != nil {
		t.Fatal("Was not able to open SCIONmessages.txt file: ", err)
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
