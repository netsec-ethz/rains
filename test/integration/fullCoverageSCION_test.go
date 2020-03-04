// +build integration

package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection/scion"
	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"github.com/scionproto/scion/go/lib/snet"
	"syscall"
)

func checkEnvAS110() {
	_, ok := os.LookupEnv("SCION_DAEMON_SOCKET")
	if !ok || scion.DefNetwork().IA.String() != "1-ff00:0:110" {
		panic("Expecting to run in tiny topo. Need to set SCION_DAEMON_SOCKET for 1-ff00:0:110.")
	}
}

func TestFullCoverageSCION(t *testing.T) {
	checkEnvAS110()

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

	checkCheckpoint(t) //make sure that caches are checkpointed

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
	checkEnvAS110()

	binDir, _ := filepath.Abs("../../build")
	pathZonepub := filepath.Join(binDir, "publisher")
	pathRainsd := filepath.Join(binDir, "rainsd")
	pathRdig := filepath.Join(binDir, "rdig")

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
	}()
	rootConfig, err := rainsd.LoadConfig("testdata/conf/SCIONnamingServerRoot.conf")
	if err != nil {
		t.Fatalf("Was not able to load namingServerRoot config: %v", err)
	}
	rootServerAddr := rootConfig.ServerAddress.Addr.String()

	cmd := exec.Command(pathRainsd,
		"./testdata/conf/SCIONnamingServerRoot.conf",
		"--id",
		"nameServerRootCLI",
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	commands = append(commands, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
	}
	log.Info("Started rainsd for", "zone", "Root", "cmd", cmd)
	time.Sleep(250 * time.Millisecond)

	cmd = exec.Command(pathZonepub,
		"./testdata/conf/SCIONpublisherRoot.conf",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		t.Fatalf("Error during zonepub: %v", err)
	}
	log.Info("Published zone for", "zone", "Root", "cmd", cmd)
	time.Sleep(1000 * time.Millisecond)

	for _, zone := range []string{"ch", "ethz.ch"} {
		cmd = exec.Command(pathRainsd,
			fmt.Sprintf("./testdata/conf/SCIONnamingServer%s.conf", zone),
			"--rootServerAddress",
			rootServerAddr,
			"--id",
			fmt.Sprintf("nameServer%sCLI", zone),
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		commands = append(commands, cmd)
		if err := cmd.Start(); err != nil {
			t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
		}
		log.Info("Started rainsd for", "zone", zone, "cmd", cmd)
		time.Sleep(250 * time.Millisecond)

		cmd = exec.Command(pathZonepub, fmt.Sprintf("./testdata/conf/SCIONpublisher%s.conf", zone))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Run(); err != nil {
			t.Fatalf("Error during zonepub: %v", err)
		}
		log.Info("Published zone for", "zone", zone, "cmd", cmd)
		time.Sleep(1000 * time.Millisecond)
	}

	// Start a resolver
	resolverConfig, err := rainsd.LoadConfig("testdata/conf/SCIONresolver.conf")
	if err != nil {
		t.Fatalf("Was not able to load resolver config: %v", err)
	}
	resolverAddr := resolverConfig.ServerAddress.Addr.(*snet.UDPAddr)
	resolverHostAddr := fmt.Sprintf("%s,%s", resolverAddr.IA, resolverAddr.Host.IP)
	resolverPort := strconv.Itoa(resolverAddr.Host.Port)

	cmd = exec.Command(pathRainsd,
		"./testdata/conf/SCIONresolver.conf",
		"--rootServerAddress",
		rootServerAddr,
		"--id",
		"resolverCLI",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	commands = append(commands, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error during rainsd %v: %v", "rainsd", err)
	}
	log.Info("Started rainsd resolver", "cmd", cmd)
	time.Sleep(1000 * time.Millisecond)

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
		cmd = exec.Command(pathRdig,
			"-p",
			resolverPort,
			fmt.Sprintf("@%s", resolverHostAddr),
			rquery.Name,
			qtype,
		)
		log.Info("Run", "cmd", cmd)
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
