package simulation

type Config struct {
	Paths                     Paths
	NofTLDs                   int
	NofRootNamingServers      int
	NofTLDNamingServers       int
	NofSLDNamingServersPerTLD int
	NofResolvers              int
	NofClients                int
	LeafZoneSize              int
	RootAddr                  string
}

type Paths struct {
	ZonefilePath    string
	CertificatePath string
	ConfigsPath     string
	KeysPath        string
}
