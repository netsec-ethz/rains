package main

import (
	"github.com/netsec-ethz/rains/rainspub"

	log "github.com/inconshreveable/log15"
)

const (
	rainspubConfigPath = "config/rainspub.conf"
)

//This package initializes and starts the server

func main() {
	err := rainspub.InitRainspub(rainspubConfigPath)
	if err != nil {
		log.Error("Error on startup", "error", err)
		panic(err)
	}
	err = rainspub.PublishInformation()
	if err != nil {
		log.Error("Was not able to publish information", "error", err)
	}
}
