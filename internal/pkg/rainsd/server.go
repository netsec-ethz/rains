package rainsd

import (
	"crypto/tls"
	"crypto/x509"

	log "github.com/inconshreveable/log15"
)

//Server represents a rainsd server instance.
type Server struct {
	//config contains configurations of this server
	config rainsdConfig
	//authority states the names over which this server has authority
	authority map[zoneContext]bool
	//certPool stores received certificates
	certPool *x509.CertPool
	//tlsCert holds the tls certificate of this server
	tlsCert tls.Certificate
	//capabilityHash contains the sha256 hash of this server's capability list
	capabilityHash string
	//capabilityList contains the string representation of this server's capability list.
	capabilityList string
	//FIXME CFE add pointer to caches to server
}

//New returns a pointer to a newly created rainsd server instance with the given config. The server
//logs with the provided level of logging.
func New(configPath string, logLevel int) (server *Server, err error) {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(logLevel), h))
	if server.config, err = loadConfig(configPath); err != nil {
		return nil, err
	}
	server.authority = make(map[zoneContext]bool)
	for i, context := range Config.ContextAuthority {
		server.authority[zoneContext{Zone: Config.ZoneAuthority[i], Context: context}] = true
	}
	if server.certPool, server.tlsCert, err = loadTLSCertificate(Config.TLSCertificateFile, Config.TLSPrivateKeyFile); err != nil {
		return nil, err
	}
	server.capabilityHash, server.capabilityList = initOwnCapabilities(server.config.Capabilities)
	if err = loadRootZonePublicKey(Config.RootZonePublicKeyPath); err != nil {
		log.Warn("Failed to load root zone public key")
		return nil, err
	}
	initCaches()
	if err = loadRootZonePublicKey(Config.RootZonePublicKeyPath); err != nil {
		log.Warn("Failed to load root zone public key")
		return nil, err
	}
	return
}

//Start starts up the server and it begins to listen for incoming connections according to its
//config.
func (s *Server) Start() error {
	if err := initQueuesAndWorkers(make(chan bool)); err != nil {
		return err
	}
	log.Debug("Successfully initiated queues and goroutines working on it")
	initEngine()
	log.Debug("Successfully initiated engine")
	// Initialize Rayhaan's tracer?
	//log.Debug("successfully initialized tracer")
	return nil
}
