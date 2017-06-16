package main

import (
	"rains/rainsd"
	"rains/rainspub"
	"time"

	log "github.com/inconshreveable/log15"
)

//This package initializes and starts the server

func main() {
	rainspub.InitRainspub()
	err := rainsd.InitServer()
	if err != nil {
		log.Error("Error on startup", "error", err)
		panic(err)
	}
	//TODO CFE add hardcoded duration to config
	go publishZoneFile(24 * time.Hour)
	rainsd.Listen()
}

func publishZoneFile(interval time.Duration) {
	//FIXME CFE what is a better solution for this? use a channel to signal when the server is finished starting up?
	time.Sleep(time.Second)
	for true {
		rainspub.PublishInformation()
		time.Sleep(interval)
	}
}
