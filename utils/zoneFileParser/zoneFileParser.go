package zoneFileParser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"rains/rainslib"
	"strconv"

	"encoding/hex"

	log "github.com/inconshreveable/log15"
)

//Parser can be used to parse RAINS zone files
type Parser struct {
}

//ParseZoneFile returns all assertions contained in the given zonefile
func (p Parser) ParseZoneFile(zoneFile []byte) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner := bufio.NewScanner(bytes.NewReader(zoneFile))
	scanner.Split(bufio.ScanWords)
	scanner.Scan()
	if scanner.Text() != ":Z:" {
		log.Warn("zoneFile malformed. It does not start with :Z:")
	}
	scanner.Scan()
	context := scanner.Text()
	scanner.Scan()
	zone := scanner.Text()
	scanner.Scan() //scan [
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
			return nil, fmt.Errorf("Expected a shard or assertion inside the zone but got=%s", scanner.Text())
		}
		scanner.Scan()
	}
	return assertions, nil
}

func parseShard(context, zone string, scanner *bufio.Scanner) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner.Scan() //scans [
	scanner.Scan()
	for scanner.Text() != "]" {
		if scanner.Text() != ":A:" {
			return nil, fmt.Errorf("zone file malformed. Expected Assertion inside shard but got=%s", scanner.Text())
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
func parseAssertion(context, zone string, scanner *bufio.Scanner) (*rainslib.AssertionSection, error) {
	scanner.Scan()
	name := scanner.Text()
	scanner.Scan() //scans [
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
				return nil, err
			}
			srvInfo.Port = uint16(portNr)
			scanner.Scan()
			prio, err := strconv.Atoi(scanner.Text())
			if err != nil {
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
			return nil, fmt.Errorf("Encountered non existing object type: %s", scanner.Text())
		}
		scanner.Scan() //scan next object type
	}
	a := &rainslib.AssertionSection{Context: context, SubjectZone: zone, SubjectName: name, Content: objects}
	log.Debug("parsed Assertion", "assertion", *a)
	return a, nil
}

func getCertObject(scanner *bufio.Scanner) (rainslib.CertificateObject, error) {
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
		Data:     scanner.Bytes(),
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
		return rainslib.ProtocolType(-1), errors.New("Encountered non existing certificate protocol type")
	}
}

func getCertUsage(certType string) (rainslib.CertificateUsage, error) {
	switch certType {
	case "2":
		return rainslib.CUTrustAnchor, nil
	case "3":
		return rainslib.CUEndEntity, nil
	default:
		return rainslib.CertificateUsage(-1), errors.New("Encountered non existing certificate usage")
	}
}

func getCertHashType(certType string) (rainslib.HashAlgorithmType, error) {
	switch certType {
	case "0":
		return rainslib.NoHashAlgo, nil
	case "1":
		return rainslib.Sha256, nil
	case "2":
		return rainslib.Sha384, nil
	case "3":
		return rainslib.Sha512, nil
	default:
		return rainslib.HashAlgorithmType(-1), errors.New("Encountered non existing certificate hash algorithm")
	}
}

func getPublicKey(scanner *bufio.Scanner) (rainslib.PublicKey, error) {
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
		return rainslib.PublicKey{}, fmt.Errorf("Encountered non existing signature algorithm type. Got:%T", keyAlgoType)
	}
	return publicKey, nil
}

func decodePublicKey(scanner *bufio.Scanner, publicKey rainslib.PublicKey) (rainslib.PublicKey, error) {
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
	return publicKey, fmt.Errorf("public key length is not 32 or 57. Got:%d", len(pKey))
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
		return rainslib.SignatureAlgorithmType(-1), fmt.Errorf("Encountered non existing signature algorithm type. Got:%s", keyAlgoType)
	}
}
