package main

import (
	"flag"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainspub"
)

var (
	config = flag.String("config", "", "Path to config file.")
)

func main() {
	flag.Parse()
	if *config == "" {
		log.Crit("-config must be specified")
		return
	}
	err := rainspub.InitRainspub(*config)
	if err != nil {
		log.Error("Error on startup", "error", err)
		panic(err)
	}
	err = rainspub.PublishInformation()
	if err != nil {
		log.Error("Was not able to publish information", "error", err)
	}
}
