package zoneFileParser

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
)

const (
	typeName        = ":name:"
	typeIP6         = ":ip6:"
	typeIP4         = ":ip4:"
	typeRedirection = ":redir:"
	typeDelegation  = ":deleg:"
	typeNameSet     = ":nameset:"
	typeCertificate = ":cert:"
	typeServiceInfo = ":srv:"
	typeRegistrar   = ":regr:"
	typeRegistrant  = ":regt:"
	typeInfraKey    = ":infra:"
	typeExternalKey = ":extra:"
	typeNextKey     = ":next:"
	keyAlgoed25519  = "ed25519"
	keyAlgoed448    = "ed448"
	keyAlgoecdsa256 = "ecdsa256"
	keyAlgoecdsa384 = "ecdsa384"
	unspecified     = "unspecified"
	ptTLS           = "tls"
	cuTrustAnchor   = "trustAnchor"
	cuEndEntity     = "endEntity"
	haNone          = "noHashAlgo"
	haSha256        = "sha256"
	haSha384        = "sha384"
	haSha512        = "sha512"
	otName          = "name"
	otIP6           = "ip6"
	otIP4           = "ip4"
	otRedirection   = "redir"
	otDelegation    = "deleg"
	otNameSet       = "nameset"
	otCertificate   = "cert"
	otServiceInfo   = "srv"
	otRegistrar     = "regr"
	otRegistrant    = "regt"
	otInfraKey      = "infra"
	otExternalKey   = "extra"
	otNextKey       = "next"
	ksRains         = "rains"
	indent4         = "    "
	indent8         = indent4 + indent4
	indent12        = indent8 + indent4
)

func init() {
	/*h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(h)*/
}

//Parser can be used to parse RAINS zone files
type Parser struct {
}

var lineNrLogger log.Logger

//Encode returns the given section represented in the zone file format if it is a zoneSection.
//In all other cases it returns the section in a displayable format similar to the zone file format
func (p Parser) Encode(s rainslib.MessageSection) string {
	return getEncoding(s, true)
}

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte, filePath string) ([]*rainslib.AssertionSection, error) {
	scanner := NewWordScanner(zoneFile)
	lineNrLogger = log.New("file", filePath, "lineNr", log.Lazy{scanner.LineNumber})
	return decodeZone(scanner)
}

//EncodeMessage transforms the given msg into a signable format.
//It must have already been verified that the msg does not contain malicious content.
//Signature meta data is not added
func (p Parser) EncodeMessage(msg *rainslib.RainsMessage) string {
	encoding := encodeMessage(msg)
	return replaceWhitespaces(encoding)
}

//EncodeSection transforms the given msg into a signable format
//It must have already been verified that the section does not contain malicious content
//Signature meta data is not added
func (p Parser) EncodeSection(s rainslib.MessageSection) string {
	encoding := getEncoding(s, true)
	return replaceWhitespaces(encoding)
}

func getEncoding(s rainslib.MessageSection, forSigning bool) string {
	encoding := ""
	switch s := s.(type) {
	case *rainslib.AssertionSection:
		encoding = encodeAssertion(s, s.Context, s.SubjectZone, indent4)
	case *rainslib.ShardSection:
		encoding = encodeShard(s, s.Context, s.SubjectZone, forSigning)
	case *rainslib.ZoneSection:
		encoding = encodeZone(s, forSigning)
	case *rainslib.QuerySection:
		encoding = encodeQuery(s)
	case *rainslib.NotificationSection:
		encoding = encodeNotification(s)
	case *rainslib.AddressAssertionSection:
		encoding = encodeAddressAssertion(s)
	case *rainslib.AddressZoneSection:
		encoding = encodeAddressZone(s)
	case *rainslib.AddressQuerySection:
		encoding = encodeAddressQuery(s)
	default:
		log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
		return ""
	}
	return encoding
}

//replaceWhitespaces replaces a single or consecutive whitespaces with a single space.
func replaceWhitespaces(encoding string) string {
	scanner := bufio.NewScanner(strings.NewReader(encoding))
	scanner.Split(bufio.ScanWords)
	var words []string
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}
	return strings.Join(words, " ")
}
