package main

import (
	"rains/rainsd"
	"rains/utils/rootZoneFile"
)

//This package initializes and starts the server

func main() {
	err := rainsd.InitServer()
	if err != nil {
		panic(err)
	}
	err = rootZoneFile.CreateRootZoneFile()
	if err != nil {
		panic(err)
	}
	rainsd.Listen()
}
