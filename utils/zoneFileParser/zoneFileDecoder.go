package zoneFileParser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

// validZone is the canonical source of truth if the provided string is a zone.
func validZone(zone string) bool {
	if zone == "." {
		return true
	}
	if !strings.HasSuffix(zone, ".") {
		return false
	}
	labels := strings.Split(zone, ".")
	for i := 0; i < len(labels)-1; i++ {
		if labels[i] == "" {
			return false
		}
	}
	return true
}

// validSubject ensures that a subject does not end with a dot, to prevent errors concatenating.
func validSubject(subject string) bool {
	return !strings.HasSuffix(subject, ".")
}

// decodeZone expects as input a scanner holding the data of a zone represented in the zone file format.
// It returns all assertions present in the zone file or an error in case the zone file is malformed.
// The error indicates what value was expected and in which line of the input the error occurred.
func decodeZone(scanner *WordScanner) ([]*rainslib.AssertionSection, error) {
	assertions := []*rainslib.AssertionSection{}
	scanner.Scan()
	if scanner.Text() != ":Z:" {
		return nil, fmt.Errorf("malformed zonefile: expected ':Z:' got: %s", scanner.TextLine())
	}
	scanner.Scan()
	zone := scanner.Text()
	if !validZone(zone) {
		return nil, fmt.Errorf("%q is not a valid zone", zone)
	}
	scanner.Scan()
	context := scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		return nil, fmt.Errorf("malformed zonefile: expected '[' got: %s", scanner.TextLine())
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		switch scanner.Text() {
		case ":A:":
			if a, err := decodeAssertion(context, zone, scanner); err != nil {
				return nil, err
			} else {
				assertions = append(assertions, a)
			}
		case ":S:":
			if a, err := decodeShard(context, zone, scanner); err != nil {
				return nil, err
			} else {
				assertions = append(assertions, a...)
			}
		default:
			return nil, fmt.Errorf("malformed zonefile: expected ':A:' or ':S:' but got %s", scanner.TextLine())
		}
		scanner.Scan() //reads in the next section's type or exit the loop in case of ']'
	}
	return assertions, nil
}

// decodeShard expects as input a scanner at a position where a shard
// represented in zone file format starts (i.e. scanner.Text() must return :S:)
// It returns all assertions present in the shard or an error in case the
// scanner holds a malformed shard i.e. it is not in zone file format
// The context and sujectZone are inherited from the zone containing the shard.
func decodeShard(context, subjectZone string, scanner *WordScanner) ([]*rainslib.AssertionSection, error) {
	if scanner.Text() != ":S:" {
		return nil, fmt.Errorf("expected shard ':S:' but got %s", scanner.TextLine())
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
		return nil, fmt.Errorf("expected '[' but got %s", scanner.TextLine())
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		if a, err := decodeAssertion(context, subjectZone, scanner); err != nil {
			return nil, err
		} else {
			assertions = append(assertions, a)
		}
		scanner.Scan()
	}
	return assertions, nil
}

// decodeZone2 expects as input a scanner holding the data of a zone represented in the zone file
// format. It returns a zone or an error in case the zone file is malformed. The error indicates
// what value was expected and in which line of the input the error occurred.
func decodeZone2(scanner *WordScanner) (*rainslib.ZoneSection, error) {
	scanner.Scan()
	if scanner.Text() != ":Z:" {
		return nil, fmt.Errorf("malformed zonefile: expected ':Z:' got: %s", scanner.TextLine())
	}
	scanner.Scan()
	zone := scanner.Text()
	if !validZone(zone) {
		return nil, fmt.Errorf("%q is not a valid zone", zone)
	}
	scanner.Scan()
	context := scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		return nil, fmt.Errorf("malformed zonefile: expected '[' got: %s", scanner.TextLine())
	}
	zoneSection := &rainslib.ZoneSection{
		SubjectZone: zone,
		Context:     context,
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		switch scanner.Text() {
		case ":A:":
			if a, err := decodeAssertion(context, zone, scanner); err != nil {
				return nil, err
			} else {
				zoneSection.Content = append(zoneSection.Content, a)
			}
		case ":S:":
			if s, err := decodeShard2(context, zone, scanner); err != nil {
				return nil, err
			} else {
				zoneSection.Content = append(zoneSection.Content, s)
			}
		default:
			return nil, fmt.Errorf("malformed zonefile: expected ':A:' or ':S:' but got %s", scanner.TextLine())
		}
		scanner.Scan() //reads in the next section's type or exit the loop in case of ']'
	}
	return zoneSection, nil
}

// decodeShard2 expects as input a scanner at a position where a shard represented in zone file
// format starts (i.e. scanner.Text() must return :S:) It returns the shard or an error in case the
// scanner holds a malformed shard i.e. it is not in zone file format The context and sujectZone are
// inherited from the zone containing the shard.
func decodeShard2(context, subjectZone string, scanner *WordScanner) (*rainslib.ShardSection, error) {
	if scanner.Text() != ":S:" {
		return nil, fmt.Errorf("expected shard ':S:' but got %s", scanner.TextLine())
	}
	scanner.Scan()
	rangeFrom := scanner.Text()
	scanner.Scan()
	rangeTo := scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		return nil, fmt.Errorf("expected '[' but got %s", scanner.TextLine())
	}
	shard := &rainslib.ShardSection{
		SubjectZone: subjectZone,
		Context:     context,
		RangeFrom:   rangeFrom,
		RangeTo:     rangeTo,
	}
	scanner.Scan()
	for scanner.Text() != "]" {
		if a, err := decodeAssertion(context, subjectZone, scanner); err != nil {
			return nil, err
		} else {
			shard.Content = append(shard.Content, a)
		}
		scanner.Scan()
	}
	return shard, nil
}

// decodeAssertion expects as input a scanner at a position where an assertion
// represented in zone file format starts (i.e. scanner.Text() must return :A:)
// It returns the assertion or an error in case the scanner holds a malformed
// assertion i.e. it is not in zone file format The context and sujectZone are
// inherited from the zone containing the assertion.  The error indicates what
// value was expected and in which line of the input the error occurred.
func decodeAssertion(context, zone string, scanner *WordScanner) (*rainslib.AssertionSection, error) {
	if scanner.Text() != ":A:" {
		return nil, fmt.Errorf("error decoding assertion: expected ':A:' but got %s", scanner.TextLine())
	}
	scanner.Scan()
	name := scanner.Text()
	if !validSubject(name) {
		return nil, fmt.Errorf("%q is not a valid subject", name)
	}
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
		return nil, fmt.Errorf("error decoding assertion: expected '[' but got %s", scanner.TextLine())
	}
	objects, err := decodeObjects(scanner)
	if err != nil {
		return nil, err
	}
	a := &rainslib.AssertionSection{Context: context, SubjectZone: zone, SubjectName: name, Content: objects}
	log.Debug("decoded Assertion", "assertion", a)
	return a, nil
}

// decodeObjects expects as input a scanner at a position where an object
// represented in zone file format starts.  It returns the object or an error
// in case the scanner holds a malformed object i.e. it is not in zone file
// format The error indicates what value was expected and in which line of the
// input the error occurred.
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
			ft, err := decodeFreeText(scanner)
			if err != nil {
				return nil, fmt.Errorf("failed reading free text for typeNameSet: %v", err)
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTNameset, Value: rainslib.NamesetExpression(ft)})
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
			ft, err := decodeFreeText(scanner)
			if err != nil {
				return nil, fmt.Errorf("failed reading free text for typeRegistrar: %v", err)
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrar, Value: ft})
			continue
		case typeRegistrant:
			ft, err := decodeFreeText(scanner)
			if err != nil {
				return nil, fmt.Errorf("failed reading free text for typeRegistrant: %v", err)
			}
			objects = append(objects, rainslib.Object{Type: rainslib.OTRegistrant, Value: ft})
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
			return nil, fmt.Errorf("malformed input: expected :<objectType>: (e.g. :ip4:) actual: %s", scanner.TextLine())
		}
		notEOF := scanner.Scan()
		if !notEOF {
			return nil, fmt.Errorf("malformed input: expected ']' but got %s", scanner.TextLine())
		}
	}
	return objects, nil
}

// decodeNameObject expects as input a scanner at a position where a nameObject
// represented in zone file format starts.  It returns the nameObject or an
// error in case the scanner holds a malformed nameObject i.e. it is not in zone
// file format The error indicates what value was expected and in which line of
// the input the error occurred.
func decodeNameObject(scanner *WordScanner) (rainslib.NameObject, error) {
	if scanner.Text() != ":name:" {
		return rainslib.NameObject{}, fmt.Errorf("expected ':name:' but got %s", scanner.TextLine())
	}
	nameObject := rainslib.NameObject{}
	scanner.Scan()
	nameObject.Name = scanner.Text()
	scanner.Scan()
	if scanner.Text() != "[" {
		return rainslib.NameObject{}, fmt.Errorf("malformed input: expected '[' but got %s", scanner.TextLine())
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
		case otNextKey:
			nameObject.Types = append(nameObject.Types, rainslib.OTNextKey)
		default:
			return rainslib.NameObject{}, fmt.Errorf("malformed object type: %s", scanner.TextLine())
		}
		notEOF := scanner.Scan()
		if !notEOF {
			return rainslib.NameObject{}, fmt.Errorf("malformed input: expected ']' but got %s", scanner.TextLine())
		}
	}
	return nameObject, nil
}

// decodeServiceInfo expects as input a scanner at a position where a srvInfo
// object represented in zone file format starts.  It returns the srvInfo object
// or an error in case the scanner holds a malformed srvInfo object i.e. it is
// not in zone file format The error indicates what value was expected and in
// which line of the input the error occurred.
func decodeServiceInfo(scanner *WordScanner) (rainslib.ServiceInfo, error) {
	if scanner.Text() != ":srv:" {
		return rainslib.ServiceInfo{}, fmt.Errorf("failed parsing serviceInfo, expected :SRV: but got %s", scanner.TextLine())
	}
	srvInfo := rainslib.ServiceInfo{}
	scanner.Scan()
	srvInfo.Name = scanner.Text()
	scanner.Scan()
	portNr, err := strconv.Atoi(scanner.Text())
	if err != nil {
		return rainslib.ServiceInfo{}, fmt.Errorf("expected port number but got %s : %v", scanner.TextLine(), err)
	}
	srvInfo.Port = uint16(portNr)
	scanner.Scan()
	prio, err := strconv.Atoi(scanner.Text())
	if err != nil {
		return rainslib.ServiceInfo{}, fmt.Errorf("expected priority number but got %s : %v", scanner.TextLine(), err)
	}
	srvInfo.Priority = uint(prio)
	return srvInfo, nil
}

// decodeFreeText expects as input a scanner at a position where a free text
// field starts.  It returns all following words separated by space until it
// encounters the next object type definition (:<type>:) or the end of the
// assertion (]).  It returns the certificate object or an error in case the
// scanner holds a malformed certificate object i.e. it is not in zone file
// format The error indicates what value was expected and in which line of the
// input the error occurred.
func decodeFreeText(scanner *WordScanner) (string, error) {
	text := ""
	scanner.Scan()
	for (!strings.HasPrefix(scanner.Text(), ":") || !strings.HasSuffix(scanner.Text(), ":")) && scanner.Text() != "]" {
		text += fmt.Sprintf("%s ", scanner.Text())
		nextEOF := scanner.Scan()
		if !nextEOF {
			return "", errors.New("unexpected EOF while parsing free text")
		}
	}
	return text[:len(text)-1], nil //remove last space
}

// decodeCertObject expects as input a scanner at a position where a certificate
// object represented in zone file format starts.  It returns the certificate
// object or an error in case the scanner holds a malformed certificate object
// i.e. it is not in zone file format The error indicates what value was
// expected and in which line of the input the error occurred.
func decodeCertObject(scanner *WordScanner) (rainslib.CertificateObject, error) {
	if scanner.Text() != ":cert:" {
		return rainslib.CertificateObject{}, fmt.Errorf("expected ':cert:' but got %s", scanner.TextLine())
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

// decodeCertPT returns the protocol type of a certificate or an error in case
// the input holds a malformed protocol type i.e. it is not in zone file format
// The error indicates what value was expected and in which line of the input
// the error occurred.
func decodeCertPT(certType string) (rainslib.ProtocolType, error) {
	switch certType {
	case unspecified:
		return rainslib.PTUnspecified, nil
	case ptTLS:
		return rainslib.PTTLS, nil
	default:
		return rainslib.ProtocolType(-1), fmt.Errorf("non existing certificate protocol type: %s", certType)
	}
}

// decodeCertUsage returns the usage type of a certificate or an error in case
// the input holds a malformed usage type i.e. it is not in zone file format The
// error indicates what value was expected and in which line of the input the
// error occurred.
func decodeCertUsage(usageType string) (rainslib.CertificateUsage, error) {
	switch usageType {
	case cuTrustAnchor:
		return rainslib.CUTrustAnchor, nil
	case cuEndEntity:
		return rainslib.CUEndEntity, nil
	default:
		return rainslib.CertificateUsage(-1), fmt.Errorf("non existing certificate usage type: %s", usageType)
	}
}

// decodeCertHashType returns the hash algorithm type or an error in case the
// input holds a malformed hash algorithm type i.e. it is not in zone file
// format The error indicates what value was expected and in which line of the
// input the error occurred.
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
		return rainslib.HashAlgorithmType(-1), fmt.Errorf("non existing certificate hash algorithm type: %s", hashType)
	}
}

// decodeDelegationKey expects as input a scanner at a position where an
// delegation object represented in zone file format starts.  It returns the
// delegation object or an error in case the scanner holds a malformed
// delegation object i.e. it is not in zone file format The error indicates
// what value was expected and in which line of the input the error occurred.
func decodeDelegationKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":deleg:" {
		return rainslib.PublicKey{}, fmt.Errorf("expected ':deleg:' but got %s", scanner.TextLine())
	}
	scanner.Scan()
	return decodeSigAlgoAndData(scanner)
}

// decodeInfraKey expects as input a scanner at a position where an infraKey
// object represented in zone file format starts.  It returns the infraKey
// object or an error in case the scanner holds a malformed infraKey object
// i.e. it is not in zone file format The error indicates what value was
// expected and in which line of the input the error occurred.
func decodeInfraKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":infra:" {
		return rainslib.PublicKey{}, fmt.Errorf("expected ':infra:' but got %s", scanner.TextLine())
	}
	scanner.Scan()
	return decodeSigAlgoAndData(scanner)
}

// decodeExternalKey expects as input a scanner at a position where an
// externalKey object represented in zone file format starts.  It returns the
// externalKey object or an error in case the scanner holds a malformed
// externalKey object i.e. it is not in zone file format The error indicates
// what value was expected and in which line of the input the error occurred.
func decodeExternalKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":extra:" {
		return rainslib.PublicKey{}, fmt.Errorf("expected :extra: but got: %s", scanner.TextLine())
	}
	scanner.Scan()
	var keySpace rainslib.KeySpaceID
	switch scanner.Text() {
	case ksRains:
		keySpace = rainslib.RainsKeySpace
	default:
		return rainslib.PublicKey{}, fmt.Errorf("expected known key type but got: %s", scanner.TextLine())
	}
	scanner.Scan()
	extra, err := decodeSigAlgoAndData(scanner)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	extra.KeySpace = keySpace
	return extra, nil
}

// decodeNextKey expects as input a scanner at a position where a nextKey
// object represented in zone file format starts.  It returns the nextKey
// object or an error in case the scanner holds a malformed nextKey object i.e.
// it is not in zone file format The error indicates what value was expected
// and in which line of the input the error occurred.
func decodeNextKey(scanner *WordScanner) (rainslib.PublicKey, error) {
	if scanner.Text() != ":next:" {
		return rainslib.PublicKey{}, fmt.Errorf("expected :next: but got %s", scanner.TextLine())
	}
	scanner.Scan()
	nextKey, err := decodeSigAlgoAndData(scanner)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	nextKey.ValidSince, err = strconv.ParseInt(scanner.Text(), 10, 64)
	if err != nil {
		return rainslib.PublicKey{}, fmt.Errorf("expected number for ValidSince but got %s : %v", scanner.TextLine(), err)
	}
	scanner.Scan()
	nextKey.ValidUntil, err = strconv.ParseInt(scanner.Text(), 10, 64)
	if err != nil {
		return rainslib.PublicKey{}, fmt.Errorf("expected number for ValidUntil but got %s : %v", scanner.TextLine(), err)
	}
	return nextKey, nil
}

// decodeSigAlgoAndData expects as input a scanner at a position where a
// signature algorithm type object represented in zone file format starts.  It
// returns a publicKey object holding the signature algorithm type and the
// public key data or an error in case the scanner holds a malformed signature
// algorithm type or malformed public key data i.e. it is not in zone file
// format The error indicates what value was expected and in which line of the
// input the error occurred.
func decodeSigAlgoAndData(scanner *WordScanner) (rainslib.PublicKey, error) {
	keyAlgoType, err := decodeKeyAlgoType(scanner.Text())
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	scanner.Scan()
	publicKey := rainslib.PublicKey{PublicKeyID: rainslib.PublicKeyID{Algorithm: keyAlgoType}}
	switch keyAlgoType {
	case rainslib.Ed25519:
		return decodeEd25519PublicKeyData(scanner.Text(), publicKey)
	case rainslib.Ed448:
		// TODO: implement ed448.
		return rainslib.PublicKey{}, errors.New("ed448 not yet implemented")
	case rainslib.Ecdsa256:
		// TODO: implement ecdsa256.
		return rainslib.PublicKey{}, errors.New("ecdsa256 not yet implemented")
	case rainslib.Ecdsa384:
		// TODO: implement ecdsa384.
		return rainslib.PublicKey{}, errors.New("ecdsa384 not yet implemented")
	default:
		return rainslib.PublicKey{}, fmt.Errorf("expected known signature algorithm but got: %s (type %s)", scanner.TextLine(), keyAlgoType)
	}
}

// decodeKeyAlgoType returns the signature algorithm type or an error in case
// the input holds a malformed signature algorithm type i.e. it is not in zone
// file format The error indicates what value was expected and in which line of
// the input the error occurred.
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
		return rainslib.SignatureAlgorithmType(-1), fmt.Errorf("non existing signature algorithm type: %s", keyAlgoType)
	}
}

// decodeEd25519PublicKeyData returns the publicKey or an error in case
// pkeyInput is malformed i.e. it is not in zone file format.
func decodeEd25519PublicKeyData(pkeyInput string, publicKey rainslib.PublicKey) (rainslib.PublicKey, error) {
	pKey, err := hex.DecodeString(pkeyInput)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	if len(pKey) == 32 {
		publicKey.Key = ed25519.PublicKey(pKey)
		return publicKey, nil
	}
	return rainslib.PublicKey{}, fmt.Errorf("wrong public key length: got %d, want: 32", len(pKey))
}
