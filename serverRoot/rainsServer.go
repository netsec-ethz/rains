package main

import (
	"github.com/netsec-ethz/rains/rainsd"

	log "github.com/inconshreveable/log15"
)

const (
	rainspubConfigPath = "config/rainspub.conf"
)

//This package initializes and starts the server

func main() {
	err := rainsd.InitServer("config/server.conf")
	if err != nil {
		log.Error("Error on startup", "error", err)
		panic(err)
	}
	rainsd.Listen()
}
