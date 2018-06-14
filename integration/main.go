package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/integration/utils"

	"github.com/netsec-ethz/rains/integration/configs"
	"github.com/netsec-ethz/rains/integration/runner"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/d4l3k/messagediff.v1"

	log "github.com/inconshreveable/log15"
)

var (
	rootPort   = flag.Uint("root_port", 2345, "Port at which to start the root server, and base for subsequent servers.")
	TLDs       = flag.String("tlds", "ch,de,com", "Comma separated list of TLDs")
	RLDs       = flag.String("rlds", "example,gov,edu", "Comma seperated list of RLDs to create in TLDs.")
	validity   = flag.Duration("validity", 30*24*time.Hour, "Validity time for signatures and assertions.")
	buildDir   = flag.String("build_dir", "build/", "Path to directory containing RAINS binaries.")
	ecdsaCurve = flag.String("ecdsa_curve", "P521", "Which ECDSA curve to use when generating X509 certificates")
	waitAfter  = flag.Bool("wait_after", false, "Wait after running tests for manual debugging of the setup")
)

func main() {
	flag.Parse()
	log.Info("Initializing system configuration files")
	tmp, err := ioutil.TempDir("", "RAINSTemp")
	if err != nil {
		log.Error(fmt.Sprintf("Failed to create temporary directory: %v", err))
		return
	}
	if err := utils.InstallBinaries(*buildDir, tmp); err != nil {
		log.Error(fmt.Sprintf("Failed to create temporary directory: %v", err))
		return
	}
	if err := initRootServer(tmp); err != nil {
		log.Error(fmt.Sprintf("Failed to initialize root server: %v", err))
		return
	}
	zonePortMap := make(map[string]uint)
	zonePortMap["."] = *rootPort
	port := uint(*rootPort + 1)
	// Initialize a level 2 server for each TLD we are supposed to run.
	TLDSlice := strings.Split(*TLDs, ",")
	for _, TLD := range TLDSlice {
		if err := generateL2Server(tmp, TLD, port); err != nil {
			log.Error(fmt.Sprintf("failed to create config for TLD server: %q: %v", TLD, err))
			return
		}
		zonePortMap[TLD] = port
		port++
		log.Info(fmt.Sprintf("Successfully created config files for server: %v", TLD))
	}
	serverExit := make(chan *runner.Runner)
	servers := make([]*runner.Runner, 0)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	// Start root server.
	rootRunner := runner.New(filepath.Join(tmp, "bin", "rainsd"),
		[]string{"--config", filepath.Join(tmp, "config", "root", "server.conf")},
		tmp, &serverExit)
	log.Info("Starting root server")
	servers = append(servers, rootRunner)
	if err := rootRunner.Execute(ctx); err != nil {
		log.Error(fmt.Sprintf("Failed to start root server: %v", err))
		return
	}
	// Start TLD servers.
	for _, TLD := range TLDSlice {
		runner := runner.New(filepath.Join(tmp, "bin", "rainsd"),
			[]string{"--config", filepath.Join(tmp, "config", TLD, "server.conf")},
			tmp, &serverExit)
		log.Info(fmt.Sprintf("Starting TLD server for %q", TLD))
		servers = append(servers, runner)
		if err := runner.Execute(ctx); err != nil {
			log.Error(fmt.Sprintf("Failed to start TLD server %q: %v", TLD, err))
			return
		}
	}
	ready := make(chan error)
	go func() {
		ready <- utils.WaitForListen(zonePortMap, 30*time.Second)
	}()
	select {
	case r := <-serverExit:
		log.Error(fmt.Sprintf("Unexpected exit of server process command %q", r.Command()), "stderr", r.Stderr())
		return
	case err := <-ready:
		if err != nil {
			log.Error(fmt.Sprintf("Failed to probe servers: %v", err))
			return
		}
	}
	log.Info("Servers successfully started. Ready to push data.")
	if err := genRootPubConf(tmp, TLDSlice, zonePortMap); err != nil {
		log.Error(fmt.Sprintf("Failed to generate root rainsPub config: %v", err))
		return
	}
	if err := runRainsPub(ctx, tmp, filepath.Join(tmp, "config", "rootPub")); err != nil {
		log.Error(fmt.Sprintf("Failed ot run root rainsPub: %v", err))
		return
	}
	log.Info("Successfully published data, now querying and verifying responses.")
	res, err := runResolve(ctx, tmp, ".", "[::1]", fmt.Sprintf("%d", zonePortMap["."]), 30*time.Second)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to run rainsdig on root zone: %v", err))
		return
	}
	pubKeyMap := make(map[string]string)
	for _, zone := range TLDSlice {
		key, err := zonePublicKey(tmp, zone)
		if err != nil {
			log.Error(fmt.Sprintf("Failed to read public key for l2 zone %q: %v", zone, err))
			return
		}
		pubKeyMap[zone] = key
	}
	if err := verifyRainsDigRoot(res, pubKeyMap); err != nil {
		log.Error(fmt.Sprintf("failed ot verify root zone entries: %v", err))
		return
	}
	log.Info(fmt.Sprintf("Successfullt ran rainsdig and got response: %s", res))
	if err := tldPub(ctx, tmp, TLDSlice, strings.Split(*RLDs, ","), zonePortMap); err != nil {
		log.Error(fmt.Sprintf("failed to publish RLD records to TLD servers: %v", err))
		return
	}
	// Query each TLD and make sure the expected entries are there.
	if err := verifyRainsDigTLD(ctx, tmp, strings.Split(*RLDs, ","), zonePortMap); err != nil {
		log.Error(fmt.Sprintf("failed to verify L2 servers: %v", err))
		return
	}
	if *waitAfter {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		log.Info("Waiting for ^C, system running for manual probing...")
		<-c
		log.Info("Shutting down")
	}
}

// tldPub generates rainspub configs for the TLD servers and pushes the registrant level domains.
func tldPub(ctx context.Context, basePath string, TLDs, RLDs []string, zonePortMap map[string]uint) error {
	for _, TLD := range TLDs {
		rainsdConfPath := filepath.Join(basePath, "config", TLD)
		privKeyPath := filepath.Join(rainsdConfPath, "private.key")
		rainsPubPath := filepath.Join(basePath, "config", fmt.Sprintf("%s_pub", TLD))
		if err := os.MkdirAll(rainsPubPath, 0700); err != nil {
			return fmt.Errorf("failed to create config dir for rainspub zone %s: %v", TLD, err)
		}
		tpp := &configs.TLDPubParams{
			TLD: TLD,
			Domains: make([]struct {
				Domain string
				IP4    string
			}, 0),
		}
		for _, domain := range RLDs {
			tpp.Domains = append(tpp.Domains, struct {
				Domain string
				IP4    string
			}{domain, "127.0.0.1"})
		}
		zone, err := tpp.Config()
		if err != nil {
			return fmt.Errorf("failed to generate TLD rainsPub config: %v", err)
		}
		zoneFile := filepath.Join(rainsPubPath, "zone")
		if err := ioutil.WriteFile(zoneFile, []byte(zone), 0600); err != nil {
			return fmt.Errorf("failed to write zone file: %v", err)
		}
		configFile := filepath.Join(rainsPubPath, "rainsPub.conf")
		port, ok := zonePortMap[TLD]
		if !ok {
			return fmt.Errorf("failed to get port for zone %s", TLD)
		}
		pubConf := &configs.RootPubConf{
			Port:           port,
			ZoneFilePath:   zoneFile,
			PrivateKeyPath: privKeyPath,
		}
		config, err := pubConf.PubConfig()
		if err != nil {
			return fmt.Errorf("failed to generate rainsPub config: %v", err)
		}
		if err := ioutil.WriteFile(configFile, []byte(config), 0600); err != nil {
			return fmt.Errorf("failed to write rainsPub config file: %v", err)
		}
		if err := runRainsPub(ctx, basePath, rainsPubPath); err != nil {
			return fmt.Errorf("failed to run rainsPub: %v", err)
		}
	}
	return nil
}

// genRootPubConf generates a rainspub configuration for the root zone data.
// l2Dirs is a slice of paths to the TLD server configuration directories,
// which is used for extracting the public keys.
func genRootPubConf(basePath string, TLDs []string, zonePortMap map[string]uint) error {
	zoneKeyMap := make(map[string]string)
	for _, TLD := range TLDs {
		zoneKeyMap[TLD] = filepath.Join(basePath, "config", TLD, "public.key")
	}
	// Build up a map of TLD -> ed25519 public key.
	pkeyMap := make(map[string]string)
	for zone, key := range zoneKeyMap {
		keyBytes, err := ioutil.ReadFile(key)
		if err != nil {
			return fmt.Errorf("failed to read public key for TLD %q: %v", zone, err)
		}
		pkeyMap[zone] = string(keyBytes)
	}
	rpp := configs.RootPubParams{
		L2TLDs: make([]struct {
			TLD       string
			PubKey    string
			RedirPort uint
		}, 0),
	}
	for zone, key := range pkeyMap {
		port, ok := zonePortMap[zone]
		if !ok {
			return fmt.Errorf("could not find port for zone %q, zonePortMap %v", zone, zonePortMap)
		}
		rpp.L2TLDs = append(rpp.L2TLDs, struct {
			TLD       string
			PubKey    string
			RedirPort uint
		}{
			zone,
			key,
			port,
		})
	}
	zoneData, err := rpp.ZoneFile()
	if err != nil {
		return fmt.Errorf("failed to generate rainsPub config for root zone: %v", err)
	}
	outDir := filepath.Join(basePath, "config", "rootPub")
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outDir, 0700); err != nil {
			return fmt.Errorf("failed to create rootPub directory: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat rootPub directory: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(outDir, "data.zone"), []byte(zoneData), 0600); err != nil {
		return fmt.Errorf("failed to write data.zone: %v", err)
	}
	rootPort, ok := zonePortMap["."]
	if !ok {
		return fmt.Errorf("could not find root port in zonePortMap: %v", zonePortMap)
	}
	rpc := configs.RootPubConf{
		Port:           rootPort,
		ZoneFilePath:   filepath.Join(outDir, "data.zone"),
		PrivateKeyPath: filepath.Join(basePath, "config", "root", "private.key"),
	}
	conf, err := rpc.PubConfig()
	if err != nil {
		return fmt.Errorf("failed to generate rainsPub config: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(outDir, "rainsPub.conf"), []byte(conf), 0600); err != nil {
		return fmt.Errorf("failed to write rainsPub.conf: %v", err)
	}
	return nil
}

// runResolve queries the specified server for the requested zone.
// The output of stdout is returned on success, otherwise an error
// is returned.
func runResolve(ctx context.Context, basePath, zone, serverHost, serverPort string, maxTime time.Duration) (string, error) {
	binPath := filepath.Join(basePath, "bin", "resolve")
	args := []string{"--insecureTLS", "-root", fmt.Sprintf("%s:%s", serverHost, serverPort), "-name", zone}
	exitChan := make(chan *runner.Runner)
	r := runner.New(binPath, args, basePath, &exitChan)
	r.Execute(ctx)
	timeout := time.After(maxTime)
	select {
	case <-exitChan:
		if r.ExitErr != nil {
			return "", fmt.Errorf("failed to run rainsDig: %v, stdErr: %s", r.ExitErr, r.Stderr())
		}
	case <-timeout:
		return "", errors.New("rainsDig execution timed out")
	}
	return r.Stdout(), nil
}

// zonePublicKey reads the ed25519 public key for the specified l2 zone.
func zonePublicKey(basePath, zone string) (string, error) {
	pathToKey := filepath.Join(basePath, "config", zone, "public.key")
	b, err := ioutil.ReadFile(pathToKey)
	if err != nil {
		return "", fmt.Errorf("failed to read public key file at %q: %v", pathToKey, err)
	}
	return string(b), nil
}

// verifyRainsDigTLD runs rainsDig for each domain in each TLD, and checks the answers.
func verifyRainsDigTLD(ctx context.Context, basePath string, RLDs []string, zonePortMap map[string]uint) error {
	for zone, port := range zonePortMap {
		if zone == "." {
			continue
		}
		for _, rld := range RLDs {
			fqdn := fmt.Sprintf("%s.%s.", rld, zone)
			output, err := runResolve(ctx, basePath, fqdn, "[::1]", fmt.Sprintf("%d", port), 10*time.Second)
			if err != nil {
				return fmt.Errorf("failed to run rainsDig: %v", err)
			}
			// XXX: Horrific hack.
			// The issue is that the zoneFileParser is not roundtripable, i.e. it cannot parse what it iself
			// has generated if the input was an assertion instead of a whole zone.
			if !strings.Contains(output, "127.0.0.1") {
				return fmt.Errorf("expected output to contain 127.0.0.1 but got: %q", output)
			}
			/*
				parser := zoneFileParser.Parser{}
				as, err := parser.Decode([]byte(output))
				if err != nil {
					return fmt.Errorf("failed to parse rainsDig output: %v", err)
				}
				if len(as) != 1 {
					return fmt.Errorf("expected %d section(s) when querying %q, but got %d", len(RLDs), fqdn, len(as))
				}
				for _, assertion := range as {
					content := assertion.Content
					if len(content) != 1 {
						return fmt.Errorf("expected 1 object in assertion for %q content but got %d", fqdn, len(content))
					}
					addr, ok := content[0].Value.(string)
					if !ok {
						return fmt.Errorf("expected value to be of type string, but got %T", content[0].Value)
					}
					// FIXME: Change this to a custom thing for each record.
					if addr != "127.0.0.1" {
						return fmt.Errorf("expected A record with value 127.0.0.1, but got: %s", addr)
					}
					glog.Infof("successfully verified %s.%s", assertion.SubjectName, assertion.SubjectZone)
				}
			*/
		}
	}
	return nil
}

// verifyRainsDigRoot checks rainsDig's output is correct for the root zone.
// subKeys is a map from TLD to public key.
func verifyRainsDigRoot(output string, subKeys map[string]string) error {
	parser := zoneFileParser.Parser{}
	as, err := parser.Decode([]byte(output))
	if err != nil {
		return fmt.Errorf("failed to parse rainsDig output: %v", err)
	}
	toCheck := len(subKeys)
	for _, assertion := range as {
		if key, ok := subKeys[assertion.SubjectName]; ok {
			content := assertion.Content
			for _, object := range content {
				switch object.Type {
				case rainslib.OTDelegation:
					value, ok := object.Value.(rainslib.PublicKey)
					if !ok {
						return fmt.Errorf("expected value type of rainslib.PublicKey but got %T: %v", object.Value, object.Value)
					}
					keyBytes := []byte(value.Key.(ed25519.PublicKey))
					wantBytes, err := hex.DecodeString(key)
					if err != nil {
						return fmt.Errorf("failed to decode expected public key to bytes: %v", err)
					}
					if diff, ok := messagediff.PrettyDiff(wantBytes, keyBytes); !ok {
						return fmt.Errorf("mismatched public keys for zone %q: diff: %s", assertion.SubjectName, diff)
					}
				}
			}
		} else {
			continue
		}
		toCheck -= 1
	}
	if toCheck != 0 {
		return fmt.Errorf("Did not receive responses for %d published zones", toCheck)
	}
	return nil
}

// publishRootZone runs rainsPub on the provided configuration directory.
// It is expected that the directory will contain rainsPub.conf.
func runRainsPub(ctx context.Context, basePath, confPath string) error {
	done := make(chan *runner.Runner)
	r := runner.New(filepath.Join(basePath, "bin", "rainspub"),
		[]string{"--config", filepath.Join(confPath, "rainsPub.conf")},
		basePath,
		&done)
	if err := r.Execute(ctx); err != nil {
		return fmt.Errorf("failed to run rainspub binary: %v", err)
	}
	timeout := time.After(30 * time.Second)
	select {
	case r := <-done:
		if r.ExitErr != nil {
			return fmt.Errorf("rainspub failed with error: %v", r.ExitErr)
		}
	case <-timeout:
		return errors.New("rainspub execution timed out")
	}
	return nil
}

// initRootServer creates the configuration files for the top level "." server.
func initRootServer(basepath string) error {
	rootConfPath := filepath.Join(basepath, "config/root/")
	if err := os.MkdirAll(rootConfPath, 0700); err != nil {
		return fmt.Errorf("failed to create root server config dir: %v", err)
	}
	delegationAssertionPath := filepath.Join(rootConfPath, "delegationAssertion.gob")
	if err := CreateDelegationAssertion(".", ".", rootConfPath, delegationAssertionPath); err != nil {
		return fmt.Errorf("failed to create delegation assertion: %v", err)
	}
	certFilePath := filepath.Join(rootConfPath, "tls.crt")
	keyFilePath := filepath.Join(rootConfPath, "tls.key")
	if err := generateX509Pair(certFilePath, keyFilePath); err != nil {
		return fmt.Errorf("failed to create x509 certificate pair: %v", err)
	}
	config := &configs.ServerConfigParams{
		ListenPort:            *rootPort,
		RootZonePublicKeyPath: delegationAssertionPath,
		TLSCertificateFile:    certFilePath,
		TLSPrivateKeyFile:     keyFilePath,
		ContextAuthority:      ".",
		ZoneAuthority:         *TLDs,
	}
	out, err := config.ServerConfig()
	if err != nil {
		return fmt.Errorf("failed to generate configuration for root server: %v", err)
	}
	configPath := filepath.Join(rootConfPath, "server.conf")
	f, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create config file %q: %v", configPath, err)
	}
	if _, err := f.WriteString(out); err != nil {
		return fmt.Errorf("failed to write server config to file: %v", err)
	}
	return nil
}

// generateL2Server creates the configuration for a second level nameserver.
func generateL2Server(basePath, TLD string, port uint) error {
	confPath := filepath.Join(basePath, "config", TLD)
	if err := os.MkdirAll(confPath, 0700); err != nil {
		return fmt.Errorf("failed to create l2 server config dir: %v", err)
	}
	delegationAssertionPath := filepath.Join(confPath, "delegationAssertion.gob")
	if err := CreateDelegationAssertion(fmt.Sprintf("%s.", TLD), ".", confPath, delegationAssertionPath); err != nil {
		return fmt.Errorf("failed to create delegation assertion: %v", err)
	}
	certFilePath := filepath.Join(confPath, "tls.crt")
	keyFilePath := filepath.Join(confPath, "tls.key")
	if err := generateX509Pair(certFilePath, keyFilePath); err != nil {
		return fmt.Errorf("failed to create x509 certificate pair: %v", err)
	}
	config := &configs.ServerConfigParams{
		ListenPort:            port,
		RootZonePublicKeyPath: delegationAssertionPath,
		TLSCertificateFile:    certFilePath,
		TLSPrivateKeyFile:     keyFilePath,
		ContextAuthority:      ".",
		ZoneAuthority:         TLD,
	}
	out, err := config.ServerConfig()
	if err != nil {
		return fmt.Errorf("failed to generate configuration for TLD %q: %v", TLD, err)
	}
	configPath := filepath.Join(confPath, "server.conf")
	f, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create config file %q: %v", configPath, err)
	}
	if _, err := f.WriteString(out); err != nil {
		return fmt.Errorf("failed to write server config to file: %v", err)
	}
	return nil
}

// generateX509Pair generates an x509 certificate and associated private key.
// The certificate is self signed.
func generateX509Pair(certOutPath, keyOutPath string) error {
	var pkey *ecdsa.PrivateKey
	var err error
	switch *ecdsaCurve {
	case "P224":
		pkey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		pkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		pkey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		pkey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return fmt.Errorf("Unsupported key type: %v", *ecdsaCurve)
	}
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA private key: %v", err)
	}
	validFrom := time.Now()
	validTill := time.Now().Add(*validity)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}
	certTmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Network Security Group", "ETH Zurich"},
		},
		NotBefore:             validFrom,
		NotAfter:              validTill,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	oBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, &certTmpl, &pkey.PublicKey, pkey)
	if err != nil {
		return fmt.Errorf("failed to generate x509 certificate: %v", err)
	}
	certOut, err := os.Create(certOutPath)
	if err != nil {
		return fmt.Errorf("failed to open certificate file: %v", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: oBytes}); err != nil {
		return fmt.Errorf("failed to convert DER bytes to PEM and write to file: %v", err)
	}
	keyOut, err := os.Create(keyOutPath)
	if err != nil {
		return fmt.Errorf("failed to open key file: %v", err)
	}
	defer keyOut.Close()
	pkeyBytes, err := x509.MarshalECPrivateKey(pkey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: pkeyBytes}); err != nil {
		return fmt.Errorf("failed to write encoded private key PEM to file: %v", err)
	}
	return nil
}

// CreateDelegationAssertion generates a new public/private key pair for the
// given context and zone. It stores the private key and a delegation assertion
// to a file. In case of root public key the assertion is self signed (zone=.)
func CreateDelegationAssertion(zone, context, outPath, gobOut string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pkey := rainslib.PublicKey{
		PublicKeyID: rainslib.PublicKeyID{
			KeySpace:  rainslib.RainsKeySpace,
			Algorithm: rainslib.Ed25519,
		},
		Key:        publicKey,
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(*validity).Unix(),
	}
	assertion := &rainslib.AssertionSection{
		Context:     context,
		SubjectZone: zone,
		SubjectName: "@",
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTDelegation, Value: pkey}},
	}
	if ok := addSignature(assertion, privateKey); !ok {
		return errors.New("Was not able to sign the assertion")
	}
	// storeKeyPair saves the public and private key.
	if err := utils.StoreKeyPair(publicKey, privateKey, outPath); err != nil {
		return err
	}
	// rainslib.Save saves the .gob file.
	return rainslib.Save(gobOut, assertion)
}

// addSignature signs the section with the public key and adds the resulting
// signature to the section.
func addSignature(a rainslib.MessageSectionWithSig, key ed25519.PrivateKey) bool {
	signature := rainslib.Signature{
		PublicKeyID: rainslib.PublicKeyID{
			Algorithm: rainslib.Ed25519,
			KeySpace:  rainslib.RainsKeySpace,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(*validity).Unix(),
	}
	return rainsSiglib.SignSection(a, key, signature, zoneFileParser.Parser{})
}

// SignDelegation signs the delegation stored at delegationPath with the
// private key stored at privateKeyPath.
func SignDelegation(delegationPath, privateKeyPath string) error {
	privateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	delegation := &rainslib.AssertionSection{}
	err = rainslib.Load(delegationPath, delegation)
	if err != nil {
		return err
	}
	if ok := addSignature(delegation, privateKey); !ok {
		return errors.New("Was not able to sign and add signature")
	}
	return rainslib.Save(delegationPath, delegation)
}
