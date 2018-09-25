package main

import (
	log "github.com/inconshreveable/log15"
)

const (
	rainspubConfigPath = "config/rainspub.conf"
)

//This package initializes and starts the server

func main() {
	err := publisher.InitRainspub(rainspubConfigPath)
	if err != nil {
		log.Error("Error on startup", "error", err)
		panic(err)
	}
	err = publisher.PublishInformation()
	if err != nil {
		log.Error("Was not able to publish information", "error", err)
	}
}
