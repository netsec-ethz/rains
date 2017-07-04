package zoneFileParser

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"rains/rainslib"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

//decodeZone decodes the zone's content and returns all contained assertions
func decodeZone(scanner *WordScanner) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner.Scan()
	if scanner.Text() != ":Z:" {
		lineNrLogger.Error("zoneFile malformed.", "expected", ":Z:", "got", scanner.Text())
		return []*rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	zone := scanner.Text()
	scanner.Scan()
	context := scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "got", scanner.Text())
		return []*rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		switch scanner.Text() {
		case ":A:":
			a, err := decodeAssertion(context, zone, scanner)
			if err != nil {
				return nil, err
			}
			assertions = append(assertions, a)
		case ":S:":
			asserts, err := decodeShard(context, zone, scanner)
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

//decodeShard decodes the shard's content and returns all contained assertions
func decodeShard(context, zone string, scanner *WordScanner) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	missingBracket := true
	//skip subjectZone and context, validFrom and validUntil if they are present
	for i := 0; i < 5; i++ {
		scanner.Scan()
		if scanner.Text() == "[" {
			missingBracket = false
			break
		}
	}
	if missingBracket {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "got", scanner.Text())
		return []*rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		if scanner.Text() != ":A:" {
			lineNrLogger.Error("zonFile malformed.", "expected", ":A:", "got", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		a, err := decodeAssertion(context, zone, scanner)
		if err != nil {
			return nil, err
		}
		assertions = append(assertions, a)
		scanner.Scan()
	}
	return assertions, nil
}

//decodeAssertion decodes the assertions content and returns an assertion section
func decodeAssertion(context, zone string, scanner *WordScanner) (*rainslib.AssertionSection, error) {
	scanner.Scan()
	name := scanner.Text()
	missingBracket := true
	//skip subjectZone and context if they are present
	for i := 0; i < 3; i++ {
		scanner.Scan()
		if scanner.Text() == "[" {
			missingBracket = false
			break
		}
	}
	if missingBracket {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "got", scanner.Text())
		return &rainslib.AssertionSection{}, errors.New("ZoneFile malformed")
	}
	objects, err := decodeObjects(scanner)
	if err != nil {
		return nil, err
	}
	a := &rainslib.AssertionSection{Context: context, SubjectZone: zone, SubjectName: name, Content: objects}
	log.Debug("decoded Assertion", "assertion", *a)
	return a, nil
}

func decodeObjects(scanner *WordScanner) ([]rainslib.Object, error) {
	scanner.Scan()
	objects := []rainslib.Object{}
	for scanner.Text() != "]" {
		switch scanner.Text() {
		case typeName:
			nameObject, err := decodeNameObject(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTName, Value: nameObject})
		case typeIP6:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTIP6Addr, Value: scanner.Text()})
		case typeIP4:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTIP4Addr, Value: scanner.Text()})
		case typeRedirection:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTRedirection, Value: scanner.Text()})
		case typeDelegation:
			delegation, err := decodePublicKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTDelegation, Value: delegation})
		case typeNameSet:
			objects = append(objects, rainslib.Object{Type: rainslib.OTNameset, Value: rainslib.NamesetExpression(decodeFreeText(scanner))})
			continue
		case typeCertificate:
			cert, err := decodeCertObject(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTCertInfo, Value: cert})
		case typeServiceInfo:
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
				lineNrLogger.Error("zonFile malformed.", "expected", "a number", "gtype", scanner.Text())
				return nil, err
			}
			srvInfo.Priority = uint(prio)
			objects = append(objects, rainslib.Object{Type: rainslib.OTServiceInfo, Value: srvInfo})
		case typeRegistrar:
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrar, Value: decodeFreeText(scanner)})
			continue
		case typeRegistrant:
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrant, Value: decodeFreeText(scanner)})
			continue
		case typeInfraKey:
			infrastructureKey, err := decodePublicKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTInfraKey, Value: infrastructureKey})
		case typeExternalKey:
			extraKey, err := decodeExternalKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTExtraKey, Value: extraKey})
		case typeNextKey:
			nextKey, err := decodeNextKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTNextKey, Value: nextKey})
		default:
			lineNrLogger.Error("zonFile malformed.", "expected", ":<objectType>: (e.g. :ip4:)", "got", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		scanner.Scan() //scan next object type
	}
	return objects, nil
}

//decodeNameObject decodes a nameObject
func decodeNameObject(scanner *WordScanner) (rainslib.NameObject, error) {
	nameObject := rainslib.NameObject{}
	scanner.Scan()
	nameObject.Name = scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "got", scanner.Text())
		return rainslib.NameObject{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		switch scanner.Text() {
		case otName:
			nameObject.Types = append(nameObject.Types, rainslib.OTName)
		case otIP6:
			nameObject.Types = append(nameObject.Types, rainslib.OTIP6Addr)
		case otIP4:
			nameObject.Types = append(nameObject.Types, rainslib.OTIP4Addr)
		case otRedirection:
			nameObject.Types = append(nameObject.Types, rainslib.OTRedirection)
		case otDelegation:
			nameObject.Types = append(nameObject.Types, rainslib.OTDelegation)
		case otNameSet:
			nameObject.Types = append(nameObject.Types, rainslib.OTNameset)
		case otCertificate:
			nameObject.Types = append(nameObject.Types, rainslib.OTCertInfo)
		case otServiceInfo:
			nameObject.Types = append(nameObject.Types, rainslib.OTServiceInfo)
		case otRegistrar:
			nameObject.Types = append(nameObject.Types, rainslib.OTRegistrar)
		case otRegistrant:
			nameObject.Types = append(nameObject.Types, rainslib.OTRegistrant)
		case otInfraKey:
			nameObject.Types = append(nameObject.Types, rainslib.OTInfraKey)
		case otExternalKey:
			nameObject.Types = append(nameObject.Types, rainslib.OTExtraKey)
		default:
			log.Warn("Unsupported object type", "type", scanner.Text())
			return rainslib.NameObject{}, errors.New("unsupported object type")
		}
		scanner.Scan()
	}
	return nameObject, nil
}

//decodeCertObject decodes a certObject
func decodeCertObject(scanner *WordScanner) (rainslib.CertificateObject, error) {
	scanner.Scan()
	certType, err := decodeCertPT(scanner.Text())
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	scanner.Scan()
	usage, err := decodeCertUsage(scanner.Text())
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	scanner.Scan()
	hashAlgo, err := decodeCertHashType(scanner.Text())
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	scanner.Scan()
	data, err := hex.DecodeString(scanner.Text())
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	cert := rainslib.CertificateObject{
		Type:     certType,
		Usage:    usage,
		HashAlgo: hashAlgo,
		Data:     data,
	}
	return cert, nil
}

//decodeCertPT decodes a certificate protocol type
func decodeCertPT(certType string) (rainslib.ProtocolType, error) {
	switch certType {
	case unspecified:
		return rainslib.PTUnspecified, nil
	case ptTLS:
		return rainslib.PTTLS, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate protocol type identifier", "got", certType)
		return rainslib.ProtocolType(-1), errors.New("encountered non existing certificate protocol type id")
	}
}

//decodeCertUsage decodes a certificate usage type
func decodeCertUsage(usageType string) (rainslib.CertificateUsage, error) {
	switch usageType {
	case cuTrustAnchor:
		return rainslib.CUTrustAnchor, nil
	case cuEndEntity:
		return rainslib.CUEndEntity, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate usage identifier", "got", usageType)
		return rainslib.CertificateUsage(-1), errors.New("encountered non existing certificate usage")
	}
}

//decodeCertHashType decodes the certificate's hash algorithm type
func decodeCertHashType(hashType string) (rainslib.HashAlgorithmType, error) {
	switch hashType {
	case haNone:
		return rainslib.NoHashAlgo, nil
	case haSha256:
		return rainslib.Sha256, nil
	case haSha384:
		return rainslib.Sha384, nil
	case haSha512:
		return rainslib.Sha512, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate hash algo identifier", "got", hashType)
		return rainslib.HashAlgorithmType(-1), errors.New("encountered non existing certificate hash algorithm")
	}
}

//decodePublicKey decodes a publicKey
func decodePublicKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	scanner.Scan()
	keyAlgoType, err := decodeKeyAlgoType(scanner.Text())
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	publicKey := rainslib.PublicKey{Type: keyAlgoType}
	switch keyAlgoType {
	case rainslib.Ed25519:
		return decodePublicKeyData(scanner, publicKey)
	case rainslib.Ed448:
		return decodePublicKeyData(scanner, publicKey)
	case rainslib.Ecdsa256:
		log.Warn("Not yet implemented")
		publicKey.Key = new(ecdsa.PublicKey)
	case rainslib.Ecdsa384:
		log.Warn("Not yet implemented")
		publicKey.Key = new(ecdsa.PublicKey)
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "key algorithm type identifier", "got", keyAlgoType)
		return rainslib.PublicKey{}, errors.New("encountered non existing signature algorithm type")
	}
	return publicKey, nil
}

//decodePublicKeyData decodes publicKeyData
func decodePublicKeyData(scanner *WordScanner, publicKey rainslib.PublicKey) (rainslib.PublicKey, error) {
	pKey, err := hex.DecodeString(scanner.Text())
	if err != nil {
		return publicKey, err
	}
	if len(pKey) == 32 {
		publicKey.Key = ed25519.PublicKey(pKey)
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

//decodeKeyAlgoType decodes a key algorithm type
func decodeKeyAlgoType(keyAlgoType string) (rainslib.SignatureAlgorithmType, error) {
	switch keyAlgoType {
	case keyAlgoed25519:
		return rainslib.Ed25519, nil
	case keyAlgoed448:
		return rainslib.Ed448, nil
	case keyAlgoecdsa256:
		return rainslib.Ecdsa256, nil
	case keyAlgoecdsa384:
		return rainslib.Ecdsa384, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "signature algorithm type identifier", "got", keyAlgoType)
		return rainslib.SignatureAlgorithmType(-1), errors.New("encountered non existing signature algorithm type")
	}
}

//FIXME CFE make it consistent with the draft
func decodeFreeText(scanner *WordScanner) string {
	text := ""
	scanner.Scan()
	for !strings.HasPrefix(scanner.Text(), ":") || !strings.HasSuffix(scanner.Text(), ":") {
		text += fmt.Sprintf("%s ", scanner.Text())
		scanner.Scan()
	}
	return text[:len(text)-1] //remove last space
}

func decodeExternalKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	scanner.Scan()
	var keySpace rainslib.KeySpaceID
	switch scanner.Text() {
	case ksRains:
		keySpace = rainslib.RainsKeySpace
	default:
		log.Warn("Unsupported key space type", "actualType", scanner.Text())
		return rainslib.PublicKey{}, errors.New("Unsupported key space type")
	}
	extra, err := decodePublicKey(scanner)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	extra.KeySpace = keySpace
	return extra, nil
}

func decodeNextKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	nextKey, err := decodePublicKey(scanner)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	nextKey.ValidSince, err = strconv.ParseInt(scanner.Text(), 10, 64)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	nextKey.ValidUntil, err = strconv.ParseInt(scanner.Text(), 10, 64)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	return nextKey, nil
}
