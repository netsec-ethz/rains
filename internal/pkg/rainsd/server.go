package rainsd

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/libresolve"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

const (
	nofReapers       = 3
	nofCheckPointers = 3
	noListeners      = 1
	shutdownChannels = nofReapers + nofCheckPointers + noListeners
)

// Server represents a rainsd server instance.
type Server struct {
	//resolver can be configured as a forwarder or perform recursive lookup by itself.
	resolver *libresolve.Resolver
	//config contains configurations of this server
	config Config
	//authority states the names over which this server has authority
	authority map[ZoneContext]bool
	//certPool stores received certificates
	certPool *x509.CertPool
	//tlsCert holds the tls certificate of this server
	tlsCert tls.Certificate
	//capabilityHash contains the sha256 hash of this server's capability list
	capabilityHash string
	//capabilityList contains the string representation of this server's capability list.
	capabilityList string
	//shutdown can be used to stop the go routines handling the input channels and closes them.
	shutdown chan bool
	//queues store the incoming sections and keeps track of how many go routines are working on it.
	queues InputQueues
	//caches contains all caches of this server
	caches *Caches
	//packetConn is the server UDP socket if we are in that mode, or nil otherwise.
	packetConn net.PacketConn
}

// New returns a pointer to a newly created rainsd server instance with the given config. The server
// logs with the provided level of logging.
func New(config Config, id string) (server *Server, err error) {
	log.Info("server New", "id", id)
	server = &Server{config: config}
	server.authority = make(map[ZoneContext]bool)
	for _, auth := range server.config.Authorities {
		server.authority[auth] = true
	}
	if server.certPool, server.tlsCert, err = loadTLSCertificate(server.config.TLSCertificateFile,
		server.config.TLSPrivateKeyFile); err != nil {
		return nil, err
	}
	server.capabilityHash, server.capabilityList = initOwnCapabilities(server.config.Capabilities)

	server.shutdown = make(chan bool, shutdownChannels)
	server.queues = InputQueues{
		Prio:    make(chan util.MsgSectionSender, server.config.PrioBufferSize),
		Normal:  make(chan util.MsgSectionSender, server.config.NormalBufferSize),
		Notify:  make(chan util.MsgSectionSender, server.config.NotificationBufferSize),
		PrioW:   make(chan struct{}, server.config.PrioWorkerCount),
		NormalW: make(chan struct{}, server.config.NormalWorkerCount),
		NotifyW: make(chan struct{}, server.config.NotificationWorkerCount),
	}
	log.Debug("Created server channels")
	server.caches = initCaches(server.config)
	if err = loadRootZonePublicKey(server.config.RootZonePublicKeyPath, server.caches.ZoneKeyCache,
		server.config.MaxCacheValidity); err != nil {
		log.Warn("Failed to load root zone public key")
		return nil, err
	}

	log.Info("Successfully initialized server", "id", id)
	return
}

// Addr returns the server's address
func (s *Server) Addr() net.Addr {
	return s.config.ServerAddress.Addr
}

func (s *Server) Config() Config {
	return s.config
}

// SetResolver adds a resolver which can forward or recursively resolve queries for this server
func (s *Server) SetResolver(resolver *libresolve.Resolver) {
	s.resolver = resolver
}

// Start starts up the server and it begins to listen for incoming connections according to its
// config.
func (s *Server) Start(monitorResources bool, id string) error {
	go s.workPrio()
	go s.workBoth()
	go s.workNotification()
	log.Debug("Goroutines working on input queue started")
	initReapers(s.config, s.caches, s.shutdown)
	if s.config.PreLoadCaches {
		loadCaches(s.config.CheckPointPath, s.caches, s.config.Authorities)
		log.Info("Caches loaded from checkpoint",
			"assertions", s.caches.AssertionsCache.Len(),
			"negAssertions", s.caches.NegAssertionCache.Len(),
			"zoneKey", s.caches.ZoneKeyCache.Len())
	}
	initStoreCachesContent(s.config, s.caches, s.shutdown)
	log.Info("Reapers and Checkpointing started")
	if monitorResources {
		go measureSystemRessources()
	}
	s.listen(id)
	return nil
}

// Shutdown closes the input channels and stops the function creating new go routines to handle the
// input. Already running worker go routines will finish eventually.
func (s *Server) Shutdown() {
	for i := 0; i < shutdownChannels; i++ {
		s.shutdown <- true
	}

	// Unblock the switchboard listener to get the shutdown message delivered
	switch s.config.ServerAddress.Type {
	case connection.TCP:
		if conn, err := net.Dial(s.Addr().Network(), s.Addr().String()); err == nil {
			conn.Close()
		}
	case connection.SCION:
		s.packetConn.Close()
	default:
		log.Warn("Unsupported Network address type.")
	}

	s.caches.ConnCache.CloseAndRemoveAllConnections()
	s.queues.Normal <- util.MsgSectionSender{}
	s.queues.Prio <- util.MsgSectionSender{}
	s.queues.Notify <- util.MsgSectionSender{}
	log.Info("Server shut down")
}
