package main

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainsd"
)

const (
	serverConfigPath = "config/server.conf"
)

//This package initializes and starts the server

func main() {
	err := rainsd.InitServer(serverConfigPath)
	if err != nil {
		log.Error("Error on startup", "error", err)
		panic(err)
	}
	rainsd.Listen()
}
