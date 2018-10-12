package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/generate"
	"golang.org/x/crypto/ed25519"
)

var (
	isRoot     = flag.Bool("isRoot", false, "Set to true if the generated assertions should be for a root zone. Default is false.")
	nofEntries = flag.Int("nofEntries", 1000, "Number of zone entries")
	name       = flag.String("name", "zonefile.txt", "Name of the zonefile")
)

//This function will panic if you try to generate a zone with more than
//3942675600 entries
func main() {
	flag.Parse()
	log.Info("Start generating zonefile")
	names := generate.LoadNames("../../../data/names.txt")
	nofNames := len(names)
	i := 0
	for nofNames < *nofEntries {
		j := i
		for nofNames < *nofEntries && j < nofNames {
			names = append(names, names[i]+"-"+names[j])
			j++
		}
		i++
	}
	output := []string{":Z: . . [\n"}
	for i := 0; i < *nofEntries; i++ {
		if *isRoot {
			pubKey, _, _ := ed25519.GenerateKey(nil)
			output = append(output, fmt.Sprintf("\t:A: %s [ :deleg: ed25519 %s ]\n", names[i], hex.EncodeToString(pubKey)))
			output = append(output, fmt.Sprintf("\t:A: %s [ :redir: ns.%s ]\n", names[i], names[i]))
			output = append(output, fmt.Sprintf("\t:A: ns.%s [ :srv: ns1.%s %d %d ]\n", names[i], names[i], rand.Intn(65536), rand.Intn(1000)))
			ip := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
			output = append(output, fmt.Sprintf("\t:A: ns1.%s [ :ip4: %s ]\n", names[i], ip))
		} else {
			//2x ipv4, 1x ipv6, 1x name or srv
			ip := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
			output = append(output, fmt.Sprintf("\t:A: ns1.%s [ :ip4: %s ]\n", names[i], ip))
			ip = fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
			output = append(output, fmt.Sprintf("\t:A: ns1.%s [ :ip4: %s ]\n", names[i], ip))
			ipv6 := fmt.Sprintf("2001:db8::%d%d%d%d:%d%d%d%d", rand.Intn(10), rand.Intn(10), rand.Intn(10),
				rand.Intn(10), rand.Intn(10), rand.Intn(10), rand.Intn(10), rand.Intn(10))
			output = append(output, fmt.Sprintf("\t:A: ns1.%s [ :ip6: %s ]\n", names[i], ipv6))
			if i%2 == 0 {
				output = append(output, fmt.Sprintf("\t:A: %s2 [ :name: %s [ ip4 ip6 ] ]\n", names[i], names[i]))
			} else {
				output = append(output, fmt.Sprintf("\t:A: srv.%s [ :srv: srv1.%s %d %d ]\n", names[i], names[i], rand.Intn(65536), rand.Intn(1000)))
			}

		}
	}
	output = append(output, "]")
	outputStr := strings.Join(output, "")
	//Write zonefile
	f, err := os.Create(*name)
	if err != nil {
		log.Error("Was not able to create file", "error", err)
		return
	}
	_, err = f.WriteString(outputStr)
	if err != nil {
		log.Error("Was not able to write file", "error", err)
		return
	}
}
