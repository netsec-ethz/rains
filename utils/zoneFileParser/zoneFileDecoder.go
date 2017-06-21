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

//decodeZone expects as input a scanner holding the data of a zone represented in the zone file format.
//It returns all assertions present in the zone file or an error in case the zone file is malformed.
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeZone(scanner *WordScanner) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner.Scan()
	if scanner.Text() != ":Z:" {
		lineNrLogger.Error("zoneFile malformed.", "expected", ":Z:", "actual", scanner.Text())
		return nil, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	zone := scanner.Text()
	scanner.Scan()
	context := scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "actual", scanner.Text())
		return nil, errors.New("ZoneFile malformed")
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
			lineNrLogger.Error("zonFile malformed.", "expected", ":A: or :S:", "actual", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		scanner.Scan() //reads in the next section's type or exit the loop in case of ']'
	}
	return assertions, nil
}

//decodeShard expects as input a scanner at a position where a shard represented in zone file format starts (i.e. scanner.Text() must return :S:)
//It returns all assertions present in the shard or an error in case the scanner holds a malformed shard i.e. it is not in zone file format
//The context and sujectZone are inherited from the zone containing the shard.
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeShard(context, subjectZone string, scanner *WordScanner) ([]*rainslib.AssertionSection, error) {
	if scanner.Text() != ":S:" {
		lineNrLogger.Error("Scanner is not at the beginning of a shard", "expected", ":S:", "actual", scanner.Text())
		return nil, errors.New("ZoneFile malformed")
	}
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
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "actual", scanner.Text())
		return nil, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		if scanner.Text() != ":A:" {
			lineNrLogger.Error("zonFile malformed.", "expected", ":A:", "actual", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		a, err := decodeAssertion(context, subjectZone, scanner)
		if err != nil {
			return nil, err
		}
		assertions = append(assertions, a)
		scanner.Scan()
	}
	return assertions, nil
}

//decodeAssertion expects as input a scanner at a position where an assertion represented in zone file format starts (i.e. scanner.Text() must return :A:)
//It returns the assertion or an error in case the scanner holds a malformed assertion i.e. it is not in zone file format
//The context and sujectZone are inherited from the zone containing the assertion.
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeAssertion(context, zone string, scanner *WordScanner) (*rainslib.AssertionSection, error) {
	if scanner.Text() != ":A:" {
		lineNrLogger.Error("Scanner is not at the beginning of an assertion", "expected", ":A:", "actual", scanner.Text())
		return nil, errors.New("ZoneFile malformed")
	}
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
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "actual", scanner.Text())
		return nil, errors.New("ZoneFile malformed")
	}
	objects, err := decodeObjects(scanner)
	if err != nil {
		return nil, err
	}
	a := &rainslib.AssertionSection{Context: context, SubjectZone: zone, SubjectName: name, Content: objects}
	log.Debug("decoded Assertion", "assertion", *a)
	return a, nil
}

//decodeObjects expects as input a scanner at a position where an object represented in zone file format starts.
//It returns the object or an error in case the scanner holds a malformed object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
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
			delegation, err := decodeDelegationKey(scanner)
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
			srvInfo, err := decodeServiceInfo(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTServiceInfo, Value: srvInfo})
		case typeRegistrar:
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrar, Value: decodeFreeText(scanner)})
			continue
		case typeRegistrant:
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrant, Value: decodeFreeText(scanner)})
			continue
		case typeInfraKey:
			infrastructureKey, err := decodeInfraKey(scanner)
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
			lineNrLogger.Error("zonFile malformed.", "expected", ":<objectType>: (e.g. :ip4:)", "actual", scanner.Text())
			return nil, errors.New("ZoneFile malformed")
		}
		scanner.Scan() //scan next object type
	}
	return objects, nil
}

//decodeNameObject expects as input a scanner at a position where a nameObject represented in zone file format starts.
//It returns the nameObject or an error in case the scanner holds a malformed nameObject i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeNameObject(scanner *WordScanner) (rainslib.NameObject, error) {
	if scanner.Text() != ":name:" {
		lineNrLogger.Error("Scanner is not at the beginning of a nameObject", "expected", ":name:", "actual", scanner.Text())
		return rainslib.NameObject{}, errors.New("ZoneFile malformed")
	}
	nameObject := rainslib.NameObject{}
	scanner.Scan()
	nameObject.Name = scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		lineNrLogger.Error("zonFile malformed.", "expected", "[", "actual", scanner.Text())
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

//decodeServiceInfo expects as input a scanner at a position where a srvInfo object represented in zone file format starts.
//It returns the srvInfo object or an error in case the scanner holds a malformed srvInfo object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeServiceInfo(scanner *WordScanner) (rainslib.ServiceInfo, error) {
	if scanner.Text() != ":srv:" {
		lineNrLogger.Error("Scanner is not at the beginning of a serviceInfo object", "expected", ":srv:", "actual", scanner.Text())
		return rainslib.ServiceInfo{}, errors.New("ZoneFile malformed")
	}
	srvInfo := rainslib.ServiceInfo{}
	scanner.Scan()
	srvInfo.Name = scanner.Text()
	scanner.Scan()
	portNr, err := strconv.Atoi(scanner.Text())
	if err != nil {
		lineNrLogger.Error("zonFile malformed.", "expected", "<a number>", "actual", scanner.Text())
		return rainslib.ServiceInfo{}, err
	}
	srvInfo.Port = uint16(portNr)
	scanner.Scan()
	prio, err := strconv.Atoi(scanner.Text())
	if err != nil {
		lineNrLogger.Error("zonFile malformed.", "expected", "<a number>", "actual", scanner.Text())
		return rainslib.ServiceInfo{}, err
	}
	srvInfo.Priority = uint(prio)
	return srvInfo, nil
}

//decodeFreeText expects as input a scanner at a position where a free text field starts.
//It returns all following words separated by space until it encounters the next object type definition (:<type>:) or the end of the assertion (]).
//It returns the certificate object or an error in case the scanner holds a malformed certificate object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeFreeText(scanner *WordScanner) string {
	text := ""
	scanner.Scan()
	for (!strings.HasPrefix(scanner.Text(), ":") || !strings.HasSuffix(scanner.Text(), ":")) && scanner.Text() != "]" {
		text += fmt.Sprintf("%s ", scanner.Text())
		scanner.Scan()
	}
	return text[:len(text)-1] //remove last space
}

//decodeCertObject expects as input a scanner at a position where a certificate object represented in zone file format starts.
//It returns the certificate object or an error in case the scanner holds a malformed certificate object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeCertObject(scanner *WordScanner) (rainslib.CertificateObject, error) {
	if scanner.Text() != ":cert:" {
		lineNrLogger.Error("Scanner is not at the beginning of a serviceInfo object", "expected", ":cert:", "actual", scanner.Text())
		return rainslib.CertificateObject{}, errors.New("ZoneFile malformed")
	}
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

//decodeCertPT returns the protocol type of a certificate or an error in case the input holds a malformed protocol type i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeCertPT(certType string) (rainslib.ProtocolType, error) {
	switch certType {
	case unspecified:
		return rainslib.PTUnspecified, nil
	case ptTLS:
		return rainslib.PTTLS, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate protocol type identifier", "actual", certType)
		return rainslib.ProtocolType(-1), errors.New("encountered non existing certificate protocol type id")
	}
}

//decodeCertUsage returns the usage type of a certificate or an error in case the input holds a malformed usage type i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeCertUsage(usageType string) (rainslib.CertificateUsage, error) {
	switch usageType {
	case cuTrustAnchor:
		return rainslib.CUTrustAnchor, nil
	case cuEndEntity:
		return rainslib.CUEndEntity, nil
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate usage identifier", "actual", usageType)
		return rainslib.CertificateUsage(-1), errors.New("encountered non existing certificate usage")
	}
}

//decodeCertHashType returns the hash algorithm type or an error in case the input holds a malformed hash algorithm type
//i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
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
		lineNrLogger.Error("zonFile malformed.", "expected", "certificate hash algo identifier", "actual", hashType)
		return rainslib.HashAlgorithmType(-1), errors.New("encountered non existing certificate hash algorithm")
	}
}

//decodeDelegationKey expects as input a scanner at a position where an delegation object represented in zone file format starts.
//It returns the delegation object or an error in case the scanner holds a malformed delegation object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeDelegationKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":deleg:" {
		lineNrLogger.Error("Scanner is not at the beginning of a extraKey object", "expected", ":deleg:", "actual", scanner.Text())
		return rainslib.PublicKey{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	return decodeSigAlgoAndData(scanner)
}

//decodeInfraKey expects as input a scanner at a position where an infraKey object represented in zone file format starts.
//It returns the infraKey object or an error in case the scanner holds a malformed infraKey object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeInfraKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":infra:" {
		lineNrLogger.Error("Scanner is not at the beginning of a extraKey object", "expected", ":infra:", "actual", scanner.Text())
		return rainslib.PublicKey{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	return decodeSigAlgoAndData(scanner)
}

//decodeExternalKey expects as input a scanner at a position where an externalKey object represented in zone file format starts.
//It returns the externalKey object or an error in case the scanner holds a malformed externalKey object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeExternalKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":extra:" {
		lineNrLogger.Error("Scanner is not at the beginning of a extraKey object", "expected", ":extra:", "actual", scanner.Text())
		return rainslib.PublicKey{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	var keySpace rainslib.KeySpaceID
	switch scanner.Text() {
	case ksRains:
		keySpace = rainslib.RainsKeySpace
	default:
		log.Warn("Unsupported key space type", "actualType", scanner.Text())
		return rainslib.PublicKey{}, errors.New("Unsupported key space type")
	}
	scanner.Scan()
	extra, err := decodeSigAlgoAndData(scanner)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	extra.KeySpace = keySpace
	return extra, nil
}

//decodeNextKey expects as input a scanner at a position where a nextKey object represented in zone file format starts.
//It returns the nextKey object or an error in case the scanner holds a malformed nextKey object i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeNextKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":next:" {
		lineNrLogger.Error("Scanner is not at the beginning of a nextKey object", "expected", ":next:", "actual", scanner.Text())
		return rainslib.PublicKey{}, errors.New("ZoneFile malformed")
	}
	scanner.Scan()
	nextKey, err := decodeSigAlgoAndData(scanner)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	nextKey.ValidSince, err = strconv.ParseInt(scanner.Text(), 10, 64)
	if err != nil {
		log.Warn("Was not able to parse validSince to int64", "expected", "<a number>", "actual", scanner.Text())
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	nextKey.ValidUntil, err = strconv.ParseInt(scanner.Text(), 10, 64)
	if err != nil {
		log.Warn("Was not able to parse validUntil to int64", "expected", "<a number>", "actual", scanner.Text())
		return rainslib.PublicKey{}, err
	}
	return nextKey, nil
}

//decodeSigAlgoAndData expects as input a scanner at a position where a signature algorithm type object represented in zone file format starts.
//It returns a publicKey object holding the signature algorithm type and the public key data
//or an error in case the scanner holds a malformed signature algorithm type or malformed public key data i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
func decodeSigAlgoAndData(scanner *WordScanner) (rainslib.PublicKey, error) {
	keyAlgoType, err := decodeKeyAlgoType(scanner.Text())
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	publicKey := rainslib.PublicKey{Type: keyAlgoType}
	switch keyAlgoType {
	case rainslib.Ed25519:
		return decodePublicKeyData(scanner.Text(), publicKey)
	case rainslib.Ed448:
		return decodePublicKeyData(scanner.Text(), publicKey)
	case rainslib.Ecdsa256:
		log.Warn("Not yet implemented")
		publicKey.Key = new(ecdsa.PublicKey)
	case rainslib.Ecdsa384:
		log.Warn("Not yet implemented")
		publicKey.Key = new(ecdsa.PublicKey)
	default:
		lineNrLogger.Error("zonFile malformed.", "expected", "key algorithm type identifier", "actual", keyAlgoType)
		return rainslib.PublicKey{}, errors.New("encountered non existing signature algorithm type")
	}
	return publicKey, nil
}

//decodeKeyAlgoType returns the signature algorithm type or an error in case the input holds a malformed signature algorithm type i.e. it is not in zone file format
//The error indicates what value was expected and in which line of the input the error occurred.
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
		lineNrLogger.Error("zonFile malformed.", "expected", "signature algorithm type identifier", "actual", keyAlgoType)
		return rainslib.SignatureAlgorithmType(-1), errors.New("encountered non existing signature algorithm type")
	}
}

//decodePublicKeyData returns the publicKey or an error in case pkeyInput is malformed i.e. it is not in zone file format
func decodePublicKeyData(pkeyInput string, publicKey rainslib.PublicKey) (rainslib.PublicKey, error) {
	pKey, err := hex.DecodeString(pkeyInput)
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
	return publicKey, fmt.Errorf("public key length is not 32 or 57. actual:%d", len(pKey))
}
