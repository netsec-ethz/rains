package main

import (
	"rains/rainsd"
	"rains/rainspub"
	"time"
)

//This package initializes and starts the server

func main() {
	rainspub.InitRainspub()
	err := rainsd.InitServer()
	if err != nil {
		panic(err)
	}
	//TODO CFE add hardcoded duration to config
	go publishZoneFile(24 * time.Hour)
	rainsd.Listen()
}

func publishZoneFile(interval time.Duration) {
	for true {
		rainspub.PublishInformation()
		time.Sleep(interval)
	}
}
