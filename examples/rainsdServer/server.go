package main

import (
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/tools/keycreator"
)

func main() {
	keycreator.DelegationAssertion(".", ".")
	server, err := rainsd.New("config/server.conf", log.LvlDebug, "0")
	if err != nil {
		log.Error(err.Error())
		return
	}
	log.Info("Server successfully initialized")
	server.Start(false)
	server.Shutdown()
}
