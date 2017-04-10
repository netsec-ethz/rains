package main

import "github.com/netsec-ethz/rains/rainsd"

//This package initializes and starts the server

func main() {
	err := rainsd.InitServer()
	if err != nil {
		panic(err)
	}
	rainsd.Listen()
}
