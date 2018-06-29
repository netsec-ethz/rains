package zonepub

import (
	"encoding/json"
	"io/ioutil"
	"time"

	log "github.com/inconshreveable/log15"
)

//loadConfig loads configuration information from configPath
func loadConfig(configPath string) error {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error("Could not open config file...", "path", configPath, "error", err)
		return err
	}
	if err = json.Unmarshal(file, &config); err != nil {
		log.Error("Could not unmarshal json format of config", "error", err)
		return err
	}
	config.AssertionValidSince *= time.Hour
	config.ShardValidSince *= time.Hour
	config.ZoneValidSince *= time.Hour
	config.DelegationValidSince *= time.Hour
	config.AssertionValidUntil *= time.Hour
	config.ShardValidUntil *= time.Hour
	config.ZoneValidUntil *= time.Hour
	config.DelegationValidUntil *= time.Hour
	return nil
}
