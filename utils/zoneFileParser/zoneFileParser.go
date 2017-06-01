package zoneFileParser

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"rains/rainslib"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
)

//Parser can be used to parse RAINS zone files
type Parser struct {
}

var lineNrLogger log.Logger

//ParseZoneFile returns all assertions contained in the given zonefile
func (p Parser) ParseZoneFile(zoneFile []byte) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner := NewWordScanner(zoneFile)
	lineNrLogger = log.New("lineNr", log.Lazy{scanner.LineNumber})
	scanner.Scan()
	if scanner.Text() != ":Z:" {
		lineNrLogger.Error("zoneFile malformed.", "expected", ":Z:", "got", scanner.Text())
		return []*rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	context := scanner.Text()
	scanner.Scan()
	zone := scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "got", scanner.Text())
		return []*rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		switch scanner.Text() {
		case ":A:":
			a, err := parseAssertion(context, zone, scanner)
			if err != nil {
				return nil, err
			}
			assertions = append(assertions, a)
		case ":S:":
			asserts, err := parseShard(context, zone, scanner)
			if err != nil {
				return nil, err
			}
			assertions = append(assertions, asserts...)
		default:
			lineNrLogger.Error("zonFile malformed.", "expected", ":A: or :S:", "got", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		scanner.Scan() //reads in the next section's type or exit the loop in case of ']'
	}
	return assertions, nil
}

func parseShard(context, zone string, scanner *WordScanner) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner.Scan()
	if scanner.Text() != "[" {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "got", scanner.Text())
		return []*rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		if scanner.Text() != ":A:" {
			lineNrLogger.Error("zonFile malformed.", "expected", ":A:", "got", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		a, err := parseAssertion(context, zone, scanner)
		if err != nil {
			return nil, err
		}
		assertions = append(assertions, a)
		scanner.Scan()
	}
	return assertions, nil
}

//parseAssertion parses the assertions content and returns an assertion section
func parseAssertion(context, zone string, scanner *WordScanner) (*rainslib.AssertionSection, error) {
	scanner.Scan()
	name := scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "got", scanner.Text())
		return &rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	objects := []rainslib.Object{}
	for scanner.Text() != "]" {
		switch scanner.Text() {
		case ":name:":
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTName, Value: scanner.Text()})
		case ":ip6:":
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTIP6Addr, Value: scanner.Text()})
		case ":ip4:":
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTIP4Addr, Value: scanner.Text()})
		case ":redir:":
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTRedirection, Value: scanner.Text()})
		case ":deleg:":
			delegation, err := getPublicKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTDelegation, Value: delegation})
		case ":nameset:":
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTNameset, Value: scanner.Text()})
		case ":cert:":
			cert, err := getCertObject(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTCertInfo, Value: cert})
		case ":srv:":
			srvInfo := rainslib.ServiceInfo{}
			scanner.Scan()
			srvInfo.Name = scanner.Text()
			scanner.Scan()
			portNr, err := strconv.Atoi(scanner.Text())
			if err != nil {
				lineNrLogger.Error("zonFile malformed.", "expected", "a number", "got", scanner.Text())
				return nil, err
			}
			srvInfo.Port = uint16(portNr)
			scanner.Scan()
			prio, err := strconv.Atoi(scanner.Text())
			if err != nil {
				lineNrLogger.Error("zonFile malformed.", "expected", "a number", "got", scanner.Text())
				return nil, err
			}
			srvInfo.Priority = uint(prio)
			objects = append(objects, rainslib.Object{Type: rainslib.OTServiceInfo, Value: srvInfo})
		case ":regr:":
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrar, Value: scanner.Text()})
		case ":regt:":
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrant, Value: scanner.Text()})
		case ":infra:":
			infrastructureKey, err := getPublicKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTDelegation, Value: infrastructureKey})
		case ":extra:":
			//TODO CFE not yet implemented
			return nil, errors.New("TODO CFE not yet implemented")
		default:
			lineNrLogger.Error("zonFile malformed.", "expected", ":<objectType>: (e.g. :ip4:)", "got", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		scanner.Scan() //scan next object type
	}
	a := &rainslib.AssertionSection{Context: context, SubjectZone: zone, SubjectName: name, Content: objects}
	log.Debug("parsed Assertion", "assertion", *a)
	return a, nil
}

func getCertObject(scanner *WordScanner) (rainslib.CertificateObject, error) {
	scanner.Scan()
	certType, err := getCertPT(scanner.Text())
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	scanner.Scan()
	usage, err := getCertUsage(scanner.Text())
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	scanner.Scan()
	hashAlgo, err := getCertHashType(scanner.Text())
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	scanner.Scan()
	cert := rainslib.CertificateObject{
		Type:     certType,
		Usage:    usage,
		HashAlgo: hashAlgo,
		Data:     []byte(scanner.Text()),
	}
	return cert, nil
}

func getCertPT(certType string) (rainslib.ProtocolType, error) {
	switch certType {
	case "0":
		return rainslib.PTUnspecified, nil
	case "1":
		return rainslib.PTTLS, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate protocol type identifier", "got", certType)
		return rainslib.ProtocolType(-1), errors.New("encountered non existing certificate protocol type id")
	}
}

func getCertUsage(usageType string) (rainslib.CertificateUsage, error) {
	switch usageType {
	case "2":
		return rainslib.CUTrustAnchor, nil
	case "3":
		return rainslib.CUEndEntity, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate usage identifier", "got", usageType)
		return rainslib.CertificateUsage(-1), errors.New("encountered non existing certificate usage")
	}
}

func getCertHashType(hashType string) (rainslib.HashAlgorithmType, error) {
	switch hashType {
	case "0":
		return rainslib.NoHashAlgo, nil
	case "1":
		return rainslib.Sha256, nil
	case "2":
		return rainslib.Sha384, nil
	case "3":
		return rainslib.Sha512, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate hash algo identifier", "got", hashType)
		return rainslib.HashAlgorithmType(-1), errors.New("encountered non existing certificate hash algorithm")
	}
}

func getPublicKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	scanner.Scan()
	keyAlgoType, err := getKeyAlgoType(scanner.Text())
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	publicKey := rainslib.PublicKey{Type: keyAlgoType}
	switch keyAlgoType {
	case rainslib.Ed25519:
		return decodePublicKey(scanner, publicKey)
	case rainslib.Ed448:
		return decodePublicKey(scanner, publicKey)
	case rainslib.Ecdsa256:
		log.Warn("Not yet implemented")
		publicKey.Key = rainslib.Ecdsa256PublicKey{}
	case rainslib.Ecdsa384:
		log.Warn("Not yet implemented")
		publicKey.Key = rainslib.Ecdsa384PublicKey{}
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "key algorithm type identifier", "got", keyAlgoType)
		return rainslib.PublicKey{}, errors.New("encountered non existing signature algorithm type")
	}
	return publicKey, nil
}

func decodePublicKey(scanner *WordScanner, publicKey rainslib.PublicKey) (rainslib.PublicKey, error) {
	pKey, err := hex.DecodeString(scanner.Text())
	if err != nil {
		return publicKey, err
	}
	if len(pKey) == 32 {
		key := rainslib.Ed25519PublicKey{}
		copy(key[:], pKey)
		publicKey.Key = key
		return publicKey, nil
	}
	if len(pKey) == 57 {
		key := rainslib.Ed448PublicKey{}
		copy(key[:], pKey)
		publicKey.Key = key
		return publicKey, nil
	}
	return publicKey, fmt.Errorf("public key length is not 32 or 57. got:%d", len(pKey))
}

func getKeyAlgoType(keyAlgoType string) (rainslib.SignatureAlgorithmType, error) {
	switch keyAlgoType {
	case "ed25519":
		return rainslib.Ed25519, nil
	case "ed448":
		return rainslib.Ed448, nil
	case "ecdsa256":
		return rainslib.Ecdsa256, nil
	case "ecdsa384":
		return rainslib.Ecdsa384, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "signature algorithm type identifier", "got", keyAlgoType)
		return rainslib.SignatureAlgorithmType(-1), errors.New("encountered non existing signature algorithm type")
	}
}

//NewWordScanner returns a WordScanner
func NewWordScanner(data []byte) *WordScanner {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanWords)
	return &WordScanner{data: data, scanner: scanner, wordsRead: 0}
}

//WordScanner uses bufio.Scanner to scan words of the input. Additionally it keeps track of the line (of the input) on which the scanner currently is
type WordScanner struct {
	data      []byte
	scanner   *bufio.Scanner
	wordsRead int
}

//Scan moves the pointer to the next token of the scan
func (ws *WordScanner) Scan() bool {
	ws.wordsRead++
	return ws.scanner.Scan()
}

//Text returns the value of the current Token as a string
func (ws *WordScanner) Text() string {
	return ws.scanner.Text()
}

//LineNumber returns the linenumber of the input data where the token pointer of the scanner currently is.
func (ws *WordScanner) LineNumber() int {
	lineScanner := bufio.NewScanner(bytes.NewReader(ws.data))
	i := 0
	lineNr := 1
	for lineScanner.Scan() && i < ws.wordsRead {
		scanner := bufio.NewScanner(strings.NewReader(lineScanner.Text()))
		scanner.Split(bufio.ScanWords)
		for scanner.Scan() {
			i++
			if i == ws.wordsRead {
				return lineNr
			}
		}
		lineNr++
	}
	return lineNr
}
