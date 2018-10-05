package main

import (
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
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
	go server.Start(false)

	config, err := publisher.LoadConfig("config/publisher.conf")
	if err != nil {
		log.Error(err.Error())
		return
	}
	pubServer := publisher.New(config)
	pubServer.Publish()

	server.Shutdown()
	log.Info("Server shut down")
}
