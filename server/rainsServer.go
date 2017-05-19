package main

import (
	"rains/rainsd"
	"rains/rainspub"
)

//This package initializes and starts the server

func main() {
	rainspub.InitRainspub()
	err := rainsd.InitServer()
	if err != nil {
		panic(err)
	}
	/*err = rootZoneFile.CreateRootZoneFile()
	if err != nil {
		panic(err)
	}*/
	//TODO CFE write a Go routine that periodically publishes the assertions from the zonefile to the rainsd server.
	rainsd.Listen()
}
