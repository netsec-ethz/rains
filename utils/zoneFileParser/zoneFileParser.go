package zoneFileParser

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
)

const (
	TypeAssertion     = ":A:"
	TypeShard         = ":S:"
	TypeZone          = ":Z:"
	TypeSignature     = ":sig:"
	TypeName          = ":name:"
	TypeIP6           = ":ip6:"
	TypeIP4           = ":ip4:"
	TypeRedirection   = ":redir:"
	TypeDelegation    = ":deleg:"
	TypeNameSet       = ":nameset:"
	TypeCertificate   = ":cert:"
	TypeServiceInfo   = ":srv:"
	TypeRegistrar     = ":regr:"
	TypeRegistrant    = ":regt:"
	TypeInfraKey      = ":infra:"
	TypeExternalKey   = ":extra:"
	TypeNextKey       = ":next:"
	TypeEd25519       = ":ed25519:"
	TypeUnspecified   = ":unspecified:"
	TypePTTLS         = ":tls:"
	TypeCUTrustAnchor = ":trustAnchor:"
	TypeCUEndEntity   = ":endEntity:"
	TypeNoHash        = ":noHash:"
	TypeSha256        = ":sha256:"
	TypeSha384        = ":sha384:"
	TypeSha512        = ":sha512:"
	TypeKSRains       = ":rains:"
	keyAlgoed448      = "ed448"
	keyAlgoecdsa256   = "ecdsa256"
	keyAlgoecdsa384   = "ecdsa384"
	otName            = "name"
	otIP6             = "ip6"
	otIP4             = "ip4"
	otRedirection     = "redir"
	otDelegation      = "deleg"
	otNameSet         = "nameset"
	otCertificate     = "cert"
	otServiceInfo     = "srv"
	otRegistrar       = "regr"
	otRegistrant      = "regt"
	otInfraKey        = "infra"
	otExternalKey     = "extra"
	otNextKey         = "next"

	indent4  = "    "
	indent8  = indent4 + indent4
	indent12 = indent8 + indent4
)

func init() {
	/*h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(h)*/
}

//Parser can be used to parse RAINS zone files
type Parser struct{}

//Encode returns the given section represented in the zone file format if it is a zoneSection.
//In all other cases it returns the section in a displayable format similar to the zone file format
func (p Parser) Encode(s rainslib.MessageSection) string {
	return GetEncoding(s, true)
}

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte) ([]*rainslib.AssertionSection, error) {
	scanner := NewWordScanner(zoneFile)
	return decodeZone(scanner)
}

//DecodeZone returns a zone exactly as it is represented in the zonefile
func (p Parser) DecodeZone(zoneFile []byte) (*rainslib.ZoneSection, error) {
	scanner := NewWordScanner(zoneFile)
	return decodeZone2(scanner)
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
	encoding := GetEncoding(s, true)
	return replaceWhitespaces(encoding)
}

//GetEncoding returns an encoding in zonefile format
func GetEncoding(s rainslib.MessageSection, forSigning bool) string {
	encoding := ""
	switch s := s.(type) {
	case *rainslib.AssertionSection:
		encoding = encodeAssertion(s, s.Context, s.SubjectZone, "", forSigning)
	case *rainslib.ShardSection:
		encoding = encodeShard(s, s.Context, s.SubjectZone, "", forSigning)
	case *rainslib.ZoneSection:
		encoding = encodeZone(s, forSigning)
	case *rainslib.QuerySection:
		encoding = encodeQuery(s)
	case *rainslib.NotificationSection:
		encoding = encodeNotification(s)
	case *rainslib.AddressAssertionSection:
		encoding = encodeAddressAssertion(s)
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
