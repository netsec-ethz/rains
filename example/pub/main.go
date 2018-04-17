package main

import (
	"flag"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainspub"
)

var (
	config = flag.String("config", "", "Path to config file.")
	// TODO: allow hostnames too for serverHost.
	serverHost    = flag.String("server", "", "IP address of the rainsd server.")
	serverPort    = flag.Int("server_port", 0, "Port of the rainsd server.")
	zoneFile      = flag.String("zone_file", "", "Path to the zone file.")
	privKey       = flag.String("priv_key", "", "Path to the private key to sign this zone with.")
	validDuration = flag.Duration("validity_duration", 24*time.Hour, "Validity of records to push.")
)

func main() {
	flag.Parse()
	if *config == "" {
		if *serverHost == "" || *serverPort == 0 || *zoneFile == "" || *privKey == "" {
			log.Crit("all other paramters must be specified if -config is not.")
			return
		}
		err := rainspub.InitFromFlags(*serverHost, *zoneFile, *privKey, *validDuration, *serverPort)
		if err != nil {
			log.Error("Error on startup", "error", err)
		}
	} else {
		err := rainspub.InitRainspub(*config)
		if err != nil {
			log.Error("Error on startup", "error", err)
			panic(err)
		}
	}
	err := rainspub.PublishInformation()
	if err != nil {
		log.Error("Was not able to publish information", "error", err)
	}
}
