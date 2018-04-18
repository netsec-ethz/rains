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

	"github.com/golang/glog"
	"github.com/netsec-ethz/rains/integration/configs"
	"github.com/netsec-ethz/rains/integration/runner"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/d4l3k/messagediff.v1"
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
	glog.Infof("Initializing system configuration files")
	tmp, err := ioutil.TempDir("", "RAINSTemp")
	if err != nil {
		glog.Fatalf("Failed to create temporary directory: %v", err)
	}
	if err := utils.InstallBinaries(*buildDir, tmp); err != nil {
		glog.Fatalf("failed to install binaries: %v", err)
	}
	if err := initRootServer(tmp); err != nil {
		glog.Fatalf("failed to initialize root server: %v", err)
	}
	zonePortMap := make(map[string]uint)
	zonePortMap["."] = *rootPort
	port := uint(*rootPort + 1)
	// Initialize a level 2 server for each TLD we are supposed to run.
	TLDSlice := strings.Split(*TLDs, ",")
	for _, TLD := range TLDSlice {
		if err := generateL2Server(tmp, TLD, port); err != nil {
			glog.Fatalf("failed to create config for TLD server %q: %v", TLD, err)
		}
		zonePortMap[TLD] = port
		port++
		glog.Infof("Successfully generated config files for server: %v", TLD)
	}
	serverExit := make(chan *runner.Runner)
	servers := make([]*runner.Runner, 0)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	// Start root server.
	rootRunner := runner.New(filepath.Join(tmp, "bin", "rainsd"),
		[]string{"--config", filepath.Join(tmp, "config", "root", "server.conf")},
		tmp, &serverExit)
	glog.Info("Starting root server")
	servers = append(servers, rootRunner)
	if err := rootRunner.Execute(ctx); err != nil {
		glog.Fatalf("Failed to start root server: %v", err)
	}
	// Start TLD servers.
	for _, TLD := range TLDSlice {
		runner := runner.New(filepath.Join(tmp, "bin", "rainsd"),
			[]string{"--config", filepath.Join(tmp, "config", TLD, "server.conf")},
			tmp, &serverExit)
		glog.Infof("Starting TLD server for %q", TLD)
		servers = append(servers, runner)
		if err := runner.Execute(ctx); err != nil {
			glog.Fatalf("Failed to start TLD server %q: %v", TLD, err)
		}
	}
	ready := make(chan error)
	go func() {
		ready <- utils.WaitForListen(zonePortMap, 30*time.Second)
	}()
	select {
	case r := <-serverExit:
		glog.Fatalf("Unexpected exit of server process command %q, stderr: %s", r.Command(), r.Stderr())
	case err := <-ready:
		if err != nil {
			glog.Fatalf("Failed to probe servers: %v", err)
		}
	}
	glog.Info("Servers successfully started. Ready to push data.")
	if err := genRootPubConf(tmp, TLDSlice, zonePortMap["."]); err != nil {
		glog.Fatalf("Failed to generate root rainsPub config: %v", err)
	}
	if err := runRainsPub(ctx, tmp, filepath.Join(tmp, "config", "rootPub")); err != nil {
		glog.Fatalf("Failed to run root rainsPub: %v", err)
	}
	glog.Info("Successfully published data, now querying and verifying responses.")
	res, err := runRainsDig(ctx, tmp, ".", "[::1]", fmt.Sprintf("%d", zonePortMap["."]), 30*time.Second)
	if err != nil {
		glog.Fatalf("Failed to run rainsDig on root zone: %v", err)
	}
	pubKeyMap := make(map[string]string)
	for _, zone := range TLDSlice {
		key, err := zonePublicKey(tmp, zone)
		if err != nil {
			glog.Fatalf("Failed to read public key for l2 zone %q: %v", zone, err)
		}
		pubKeyMap[zone] = key
	}
	if err := verifyRainsDigRoot(res, pubKeyMap); err != nil {
		glog.Fatalf("failed to verify root zone entries: %v", err)
	}
	glog.Infof("Successfully ran rainsDig and got response: %s", res)
	if err := tldPub(ctx, tmp, TLDSlice, strings.Split(*RLDs, ","), zonePortMap); err != nil {
		glog.Fatalf("failed to RLD records to TLD servers: %v", err)
	}
	// Query each TLD and make sure the expected entries are there.
	if err := verifyRainsDigTLD(ctx, tmp, strings.Split(*RLDs, ","), zonePortMap); err != nil {
		glog.Fatalf("failed to verify L2 servers with rainsdig: %v", err)
	}
	if *waitAfter {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		glog.Infof("Waiting for ^C, do your manual poking now...")
		<-c
		glog.Infof("Shutting down")
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
func genRootPubConf(basePath string, TLDs []string, rootPort uint) error {
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
			TLD    string
			PubKey string
		}, 0),
	}
	for zone, key := range pkeyMap {
		glog.Infof("Adding zone: %s, key: %s", zone, key)
		rpp.L2TLDs = append(rpp.L2TLDs, struct {
			TLD    string
			PubKey string
		}{
			zone,
			key,
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

// runRainsDig queries the specified server for the requested zone.
// The output of stdout is returned on success, otherwise an error
// is returned.
func runRainsDig(ctx context.Context, basePath, zone, serverHost, serverPort string, maxTime time.Duration) (string, error) {
	binPath := filepath.Join(basePath, "bin", "rainsdig")
	args := []string{"--insecureTLS", "-s", serverHost, "-p", serverPort}
	if zone != "." {
		args = append(args, "-q", zone)
	}
	glog.Infof("Running rainsdig with arguments: %v", args)
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
		fqdn := fmt.Sprintf(".%s.", zone)
		output, err := runRainsDig(ctx, basePath, fqdn, "[::1]", fmt.Sprintf("%d", port), 10*time.Second)
		if err != nil {
			return fmt.Errorf("failed to run rainsDig: %v", err)
		}
		parser := zoneFileParser.Parser{}
		as, err := parser.Decode([]byte(output))
		if err != nil {
			return fmt.Errorf("failed to parse rainsDig output: %v", err)
		}
		if len(as) != len(RLDs) {
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
		glog.Infof("subjectName = %s", assertion.SubjectName)
		if key, ok := subKeys[assertion.SubjectName]; ok {
			content := assertion.Content
			if len(content) > 1 {
				return fmt.Errorf("expected content length for subject=%s to be 1 but got %d", assertion.SubjectName, len(content))
			}
			if _, ok := content[0].Value.(rainslib.PublicKey); !ok {
				return fmt.Errorf("expected value of type rainslib.PublicKey but got %T", content[0].Value)
			}
			pkey := content[0].Value.(rainslib.PublicKey)
			if _, ok := pkey.Key.(ed25519.PublicKey); !ok {
				return fmt.Errorf("expected key of type ed25519.PublcKey but got %T", pkey.Key)
			}
			keyBytes := []byte(pkey.Key.(ed25519.PublicKey))
			wantBytes, err := hex.DecodeString(key)
			if err != nil {
				return fmt.Errorf("failed to decode expected public key to bytes: %v", err)
			}
			if diff, ok := messagediff.PrettyDiff(wantBytes, keyBytes); !ok {
				return fmt.Errorf("mismatched public keys for zone %q: diff: %s", assertion.SubjectName, diff)
			}
			glog.Infof("Key successfully verified for zone %s", assertion.SubjectName)
		} else {
			return fmt.Errorf("got unknown sub zone: %s", assertion.SubjectName)
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
	glog.Infof("Rainspub successfully exited, stdout: %v", r.Stdout())
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
	glog.Infof("Generated root public Key: %v", publicKey)
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

// CreateEd25519Keypair creates a ed25519 keypair where it stores the keys
// hexadecimal encoded to privateKeyPath or publicKeyPath respectively.
func CreateEd25519Keypair(privateKeyPath, publicKeyPath string) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		glog.Errorf("Could not create key pair: %v", err)
		return
	}
	err = ioutil.WriteFile(privateKeyPath, []byte(hex.EncodeToString(privateKey)), 0644)
	if err != nil {
		glog.Errorf("Could not store private key to %q: %v", privateKeyPath, err)
	}
	err = ioutil.WriteFile(publicKeyPath, []byte(hex.EncodeToString(publicKey)), 0644)
	if err != nil {
		glog.Errorf("Could not store public key %q: %v", publicKeyPath, err)
	}
}
