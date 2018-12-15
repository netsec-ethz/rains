package main

import (
	"flag"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/tools/keycreator"
)

var (
	configPath = flag.String("config", "config/server.conf", "Path to config file.")
)

func main() {
	flag.Parse()
	keycreator.DelegationAssertion(".", ".", "keys/selfSignedRootDelegationAssertion.gob", "keys/rootPrivateKey.txt")
	server, err := rainsd.New(*configPath, "0")
	if err != nil {
		log.Error(err.Error())
		return
	}
	log.Info("Server successfully initialized")
	go server.Start(false)
	time.Sleep(time.Hour)
	server.Shutdown()
	log.Info("Server shut down")
}
