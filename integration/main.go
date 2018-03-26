package main

import (
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
	"path/filepath"
	"time"

	"github.com/golang/glog"
	"github.com/netsec-ethz/rains/integration/configs"
	"github.com/netsec-ethz/rains/rainsSiglib"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
	"golang.org/x/crypto/ed25519"
)

var (
	l2TLDs     = flag.String("l2TLDs", "ch,de,com", "Comma separated list of level 2 TLDs")
	validity   = flag.Duration("validity", 30*24*time.Hour, "Validity time for signatures and assertions.")
	buildDir   = flag.String("buildDir", "build/", "Path to directory containing RAINS binaries.")
	ecdsaCurve = flag.String("ecdsa_curve", "P521", "Which ECDSA curve to use when generating X509 certificates")
)

func main() {
	flag.Parse()
	glog.Infof("Initializing system configuration files")
	tmp, err := ioutil.TempDir("", "RAINSTemp")
	if err != nil {
		glog.Fatalf("Failed to create temporary directory: %v", err)
	}
	if err := installBinaries(tmp); err != nil {
		glog.Fatalf("failed to install binaries: %v", err)
	}
	if err := initRootServer(tmp); err != nil {
		glog.Fatalf("failed to initialize root server: %v", err)
	}
	// TODO: implement l2tld server generator.
	// Initialize a level 2 server for each l2TLD we are supposed to run.
	/*
		for _, l2TLD := range *l2TLDs {

		}
	*/
}

// installBinaries copies rainsd, rainspub, rainsdig to the temporary path.
func installBinaries(tmpDir string) error {
	outBin := filepath.Join(tmpDir, "bin/")
	if err := os.Mkdir(outBin, 0766); err != nil {
		return fmt.Errorf("failed to create bin directory: %v", err)
	}
	requiredBins := []string{"rainsd", "rainspub", "rainsdig"}
	for _, bin := range requiredBins {
		if err := copyBinTmp(bin, outBin); err != nil {
			return fmt.Errorf("failed to copy binary to tmp dir %q: %v", outBin, err)
		}
	}
	return nil
}

func copyBinTmp(bin, outPath string) error {
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("failed to stat bin to copy: %v", err)
	}
	b, err := ioutil.ReadFile(filepath.Join(*buildDir, bin))
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(outPath, bin), b, 0700); err != nil {
		return fmt.Errorf("failed to copy binary into tmp folder: %v", err)
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
		return fmt.Errorf("Failed to create delegation assertion: %v", err)
	}
	certFilePath := filepath.Join(rootConfPath, "tls.crt")
	keyFilePath := filepath.Join(rootConfPath, "tls.key")
	if err := generateX509Pair(certFilePath, keyFilePath); err != nil {
		return fmt.Errorf("failed to create x509 certificate pair: %v", err)
	}
	config := &configs.ServerConfigParams{
		ListenPort:            2345,
		RootZonePublicKeyPath: delegationAssertionPath,
		TLSCertificateFile:    certFilePath,
		TLSPrivateKeyFile:     keyFilePath,
		ContextAuthority:      ".",
		ZoneAuthority:         *l2TLDs,
	}
	out, err := config.ServerConfig()
	if err != nil {
		return fmt.Errorf("failed to generate configuration for root server: %v", err)
	}
	configPath := filepath.Join(rootConfPath, "server.conf")
	f, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %q: %v", configPath, err)
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
func CreateDelegationAssertion(context, zone, outPath, gobOut string) error {
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
	if zone == "." {
		if ok := addSignature(assertion, privateKey); !ok {
			return errors.New("Was not able to sign the assertion")
		}
	}
	// storeKeyPair saves the public and private key.
	if err := storeKeyPair(publicKey, privateKey, outPath); err != nil {
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

// storeKeyPair stores public/private keypair in hex to two files.
func storeKeyPair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, outPath string) error {
	privateKeyEnc := make([]byte, hex.EncodedLen(len(privateKey)))
	hex.Encode(privateKeyEnc, privateKey)
	err := ioutil.WriteFile(filepath.Join(outPath, "private.key"), privateKeyEnc, 0600)
	if err != nil {
		return err
	}
	publicKeyEnc := make([]byte, hex.EncodedLen(len(publicKey)))
	hex.Encode(publicKeyEnc, publicKey)
	err = ioutil.WriteFile(filepath.Join(outPath, "public.key"), publicKeyEnc, 0600)
	return err
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
