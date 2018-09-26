package main

import (
	"flag"
	"os"

	log "github.com/inconshreveable/log15"
)

//TODO add default values to description
var folderPath = flag.String("n", "../../examples/test", "sets the server's folder name")

//main parses the input flags, creates a query, send the query to the server defined in the input, waits for a response and writes the result to the command line.
func main() {
	flag.Parse()
	if _, err := os.Stat(*folderPath); os.IsNotExist(err) {
		//create folder structure
		os.Mkdir(*folderPath, 0775)
		serverPath := *folderPath + "/rainsServer"
		os.Mkdir(serverPath, 0775)
		os.Mkdir(serverPath+"/config", 0775)
		os.Mkdir(serverPath+"/keys", 0775)

		pubPath := *folderPath + "/rainsPub"
		os.Mkdir(pubPath, 0775)
		os.Mkdir(pubPath+"/config", 0775)
		os.Mkdir(pubPath+"/keys", 0775)
		os.Mkdir(pubPath+"/zoneFiles", 0775)

		//copy file, make helper function
		//create file
		//copy content
		//os.sync -> write to memory

	} else {
		log.Error("Folder already exists")
	}
}
