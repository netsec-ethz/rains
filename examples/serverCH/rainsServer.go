package main

import (
	"flag"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
)

const (
	serverConfigPath = "config/server.conf"
)

var logLvl = flag.String("logLvl", log.LvlInfo.String(), "sets the server's logging level.")

//This package initializes and starts the server

func main() {
	flag.Parse()
	lvl, err := log.LvlFromString(*logLvl)
	if err != nil {
		log.Error("Error on startup. Unsupported logging level", "error", err)
		panic(err)
	}
	err = rainsd.InitServer(serverConfigPath, int(lvl))
	if err != nil {
		log.Error("Error on startup", "error", err)
		panic(err)
	}
	rainsd.Listen()
}
