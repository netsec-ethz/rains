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

const (
	otName          = ":name:"
	otIP6           = ":ip6:"
	otIP4           = ":ip4:"
	otRedirection   = ":redir:"
	otDelegation    = ":deleg:"
	otNameSet       = ":nameset:"
	otCertificate   = ":cert:"
	otServiceInfo   = ":srv:"
	otRegistrar     = ":regr:"
	otRegistrant    = ":regt:"
	otInfraKey      = ":infra:"
	otExternalKey   = ":extra:"
	keyAlgoed25519  = "ed25519"
	keyAlgoed448    = "ed448"
	keyAlgoecdsa256 = "ecdsa256"
	keyAlgoecdsa384 = "ecdsa384"
)

var lineNrLogger log.Logger

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte, filePath string) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner := NewWordScanner(zoneFile)
	lineNrLogger = log.New("file", filePath, "lineNr", log.Lazy{scanner.LineNumber})
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
		case otName:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTName, Value: scanner.Text()})
		case otIP6:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTIP6Addr, Value: scanner.Text()})
		case otIP4:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTIP4Addr, Value: scanner.Text()})
		case otRedirection:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTRedirection, Value: scanner.Text()})
		case otDelegation:
			delegation, err := getPublicKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTDelegation, Value: delegation})
		case otNameSet:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTNameset, Value: scanner.Text()})
		case otCertificate:
			cert, err := getCertObject(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTCertInfo, Value: cert})
		case otServiceInfo:
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
		case otRegistrar:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrar, Value: scanner.Text()})
		case otRegistrant:
			scanner.Scan()
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrant, Value: scanner.Text()})
		case otInfraKey:
			infrastructureKey, err := getPublicKey(scanner)
			if err != nil {
				return nil, err
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTDelegation, Value: infrastructureKey})
		case otExternalKey:
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

//Encode returns the given zone represented in the zone file format
func (p Parser) Encode(zone *rainslib.ZoneSection) string {
	log.Warn("Not yet implemented")
	//TODO CFE replace multiple spaces with just one. e.g. for contained shards and assertions when context and zone are not present there are 3 spaces.
	//This way the code is much cleaner
	return ""
}

func encodeObjects(o []rainslib.Object, indent string) string {
	objects := ""
	for _, obj := range o {
		switch obj.Type {
		case rainslib.OTName:
			if nameObj, ok := obj.Value.(rainslib.NameObject); ok {
				objects += fmt.Sprintf("%s %s\n", otDelegation, nameObj.Name)
				//FIXME CFE Add object Types
				//It is incorrectly implemented in the decoder, fix it also there!
				//
			}
			log.Warn("Type assertion failed. Expected rainslib.NameObject", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTIP6Addr:
			objects += fmt.Sprintf("%s %s\n", otIP6, obj.Value)
		case rainslib.OTIP4Addr:
			objects += fmt.Sprintf("%s %s\n", otIP4, obj.Value)
		case rainslib.OTRedirection:
			objects += fmt.Sprintf("%s %s\n", otRedirection, obj.Value)
		case rainslib.OTDelegation:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				objects += fmt.Sprintf("%s %s\n", otDelegation, encodePublicKey(pkey))
			}
			log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTNameset:
			objects += fmt.Sprintf("%s %s\n", otNameSet, obj.Value)
		case rainslib.OTCertInfo:
			if cert, ok := obj.Value.(rainslib.CertificateObject); ok {
				objects += fmt.Sprintf("%s %s\n", otCertificate)
				//FIXME CFE TO IMPLEMENT
				//
				//
			}
			log.Warn("Type assertion failed. Expected rainslib.CertificateObject", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTServiceInfo:
			if srvInfo, ok := obj.Value.(rainslib.ServiceInfo); ok {
				objects += fmt.Sprintf("%s %s %d %d\n", otDelegation, srvInfo.Name, srvInfo.Port, srvInfo.Priority)
			}
			log.Warn("Type assertion failed. Expected rainslib.ServiceInfo", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTRegistrar:
			objects += fmt.Sprintf("%s %s\n", otRegistrar, obj.Value)
		case rainslib.OTRegistrant:
			objects += fmt.Sprintf("%s %s\n", otRegistrant, obj.Value)
		case rainslib.OTInfraKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				objects += fmt.Sprintf("%s %s\n", otInfraKey, encodePublicKey(pkey))
			}
			log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
		case rainslib.OTExtraKey:
			if pkey, ok := obj.Value.(rainslib.PublicKey); ok {
				objects += fmt.Sprintf("%s %s\n", otExternalKey, encodePublicKey(pkey))
			}
			log.Warn("Type assertion failed. Expected rainslib.PublicKey", "actualType", fmt.Sprintf("%T", obj.Value))
		default:
			log.Warn("Unsupported obj type", "type", fmt.Sprintf("%T", obj.Type))
		}
	}
	return objects
}

func encodePublicKey(pkey rainslib.PublicKey) string {
	switch pkey.Type {
	case rainslib.Ed25519:
		if key, ok := pkey.Key.(rainslib.Ed25519PublicKey); ok {
			return fmt.Sprintf("%s %s", keyAlgoed25519, hex.EncodeToString(key[:]))
		}
		log.Warn("Type assertion failed. Expected rainslib.Ed25519PublicKey", "actualType", fmt.Sprintf("%T", pkey.Key))
	case rainslib.Ed448:
		if key, ok := pkey.Key.(rainslib.Ed448PublicKey); ok {
			return fmt.Sprintf("%s %s", keyAlgoed448, hex.EncodeToString(key[:]))
		}
		log.Warn("Type assertion failed. Expected rainslib.Ed448PublicKey", "type", fmt.Sprintf("%T", pkey.Key))
	case rainslib.Ecdsa256:
		log.Warn("Not yet implemented")
		return ""
	case rainslib.Ecdsa384:
		log.Warn("Not yet implemented")
		return ""
	default:
		log.Warn("Unsupported signature algorithm type")

	}
	return ""
}

func encodeAssertion(a *rainslib.AssertionSection, context, zone string) string {
	assertion := fmt.Sprintf(":A: %s %s %s [", context, zone, a.SubjectName)
	if len(a.Content) > 1 {
		return fmt.Sprintf("%s\n%s]", assertion, encodeObjects(a.Content, "\t\t\t"))
	}
	return fmt.Sprintf("%s %s ]", assertion, encodeObjects(a.Content, ""))
}

func encodeShard(s *rainslib.ShardSection, context, zone string, toSign bool) string {
	shard := fmt.Sprintf(":S: %s %s %s %s [\n", context, zone, s.RangeFrom, s.RangeTo)
	for _, assertion := range s.Content {
		ctx, subjectZone := getContextAndZone(context, zone, assertion, toSign)
		shard += fmt.Sprintf("\t\t%s\n", encodeAssertion(assertion, ctx, subjectZone))
	}
	return fmt.Sprintf("%s]", shard)
}

func encodeZone(z *rainslib.ZoneSection, toSign bool) string {
	zone := fmt.Sprintf(":Z: %s %s [\n", z.Context, z.SubjectZone)
	for _, section := range z.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			context, subjectZone := getContextAndZone(z.Context, z.SubjectZone, section, toSign)
			zone += fmt.Sprintf("\t%s\n", encodeAssertion(section, context, subjectZone))
		case *rainslib.ShardSection:
			context, subjectZone := getContextAndZone(z.Context, z.SubjectZone, section, toSign)
			zone += fmt.Sprintf("\t%s\n", encodeShard(section, context, subjectZone, toSign))
		default:
			log.Warn("Unsupported message section type", "msgSection", section)
		}
	}
	return fmt.Sprintf("%s]", zone)
}

func getContextAndZone(outerContext, outerZone string, containedSection rainslib.MessageSectionWithSigForward, toSign bool) (string, string) {
	context := containedSection.GetContext()
	subjectZone := containedSection.GetSubjectZone()
	if toSign && (context == "" || subjectZone == "") {
		context = outerContext
		subjectZone = outerZone
	}
	return context, subjectZone
}
