package main

import (
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
)

func main() {
	server, err := rainsd.New("config/server.conf", log.LvlDebug)
	if err != nil {
		log.Error(err.Error())
		return
	}
	log.Error("Server successfully initialized")
	server.Start()
	server.Shutdown()
}
