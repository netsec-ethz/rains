package utils

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/golang/glog"
	"golang.org/x/crypto/ed25519"
)

// WaitForListen takes a map of zones and ports, and tries connecting to each
// port on tcp://[::1]:<port>. If no TCP connection is established after the
// specified timeout then an error is returned.
func WaitForListen(zonePortMap map[string]uint, timeoutAfter time.Duration) error {
	giveupAt := time.Now().Add(timeoutAfter)
	var conn net.Conn
	var err error
	for _, port := range zonePortMap {
		addr := fmt.Sprintf("[::1]:%d", port)
		for time.Now().Before(giveupAt) {
			conn, err = net.Dial("tcp", addr)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			glog.Infof("Successfully probed server at: %v", addr)
			conn.Close()
			break
		}
		if err != nil {
			return fmt.Errorf("failed to connect to %q: %v", addr, err)
		}
	}
	return nil
}

// installBinaries copies rainsd, rainspub, rainsdig to the temporary path.
// It is assumed that the binaries can be found at $PWD/build/.
func InstallBinaries(buildDir, tmpDir string) error {
	outBin := filepath.Join(tmpDir, "bin/")
	if err := os.Mkdir(outBin, 0766); err != nil {
		return fmt.Errorf("failed to create bin directory: %v", err)
	}
	requiredBins := []string{"rainsd", "rainspub", "rainsdig"}
	for _, bin := range requiredBins {
		if err := copyBinTmp(buildDir, bin, outBin); err != nil {
			return fmt.Errorf("failed to copy binary to tmp dir %q: %v", outBin, err)
		}
	}
	return nil
}

func copyBinTmp(buildDir, bin, outPath string) error {
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("failed to stat bin to copy: %v", err)
	}
	b, err := ioutil.ReadFile(filepath.Join(buildDir, bin))
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(outPath, bin), b, 0700); err != nil {
		return fmt.Errorf("failed to copy binary into tmp folder: %v", err)
	}
	return nil
}

// StoreKeyPair stores public/private keypair in hex to two files.
func StoreKeyPair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, outPath string) error {
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
