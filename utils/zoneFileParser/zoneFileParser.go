package zoneFileParser

import (
	"bufio"
	"bytes"
	"errors"
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
	return GetEncoding(s, false)
}

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte) ([]rainslib.MessageSectionWithSigForward, error) {
	log.Error("Not yet supported")
	return nil, nil
}

//DecodeZone returns a zone exactly as it is represented in the zonefile
func (p Parser) DecodeZone(zoneFile []byte) (*rainslib.ZoneSection, error) {
	lines := removeComments(bufio.NewScanner(bytes.NewReader(zoneFile)))
	log.Debug("Preprocessed input", "data", lines)
	parser := ZFPNewParser()
	parser.Parse(&ZFPLex{lines: lines})
	zone, ok := parser.Result()[0].(*rainslib.ZoneSection)
	if !ok {
		return nil, errors.New("First element of zonefile is not a zone. (Note, only the first element of the zonefile is considered)")
	}
	return zone, nil
}

//EncodeMessage transforms the given msg into a signable format.
//It must have already been verified that the msg does not contain malicious content.
//Signature meta data is not added
func (p Parser) EncodeMessage(msg *rainslib.RainsMessage) []byte {
	encoding := encodeMessage(msg)
	return []byte(replaceWhitespaces(encoding))
}

//EncodeSection transforms the given msg into a signable format
//It must have already been verified that the section does not contain malicious content
//Signature meta data is not added
func (p Parser) EncodeSection(s rainslib.MessageSectionWithSig) []byte {
	encoding := GetEncoding(s, true)
	return []byte(replaceWhitespaces(encoding))
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
