package zoneFileParser

import (
	"rains/rainslib"

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
	ksRains         = "rains"
	indent4         = "    "
	indent8         = indent4 + indent4
	indent12        = indent8 + indent4
)

func init() {
	h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(h)
}

//Parser can be used to parse RAINS zone files
type Parser struct {
}

var lineNrLogger log.Logger

//Encode returns the given zone represented in the zone file format
func (p Parser) Encode(zone *rainslib.ZoneSection) string {
	return encodeZone(zone, false)
}

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte, filePath string) ([]*rainslib.AssertionSection, error) {
	scanner := NewWordScanner(zoneFile)
	lineNrLogger = log.New("file", filePath, "lineNr", log.Lazy{scanner.LineNumber})
	return decodeZone(scanner)
}
