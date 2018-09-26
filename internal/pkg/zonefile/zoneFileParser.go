package zonefile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/sections"

	log "github.com/inconshreveable/log15"
)

const (
	TypeAssertion     = ":A:"
	TypeShard         = ":S:"
	TypePshard        = ":P:"
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
	TypeFnv64         = ":fnv64:"
	TypeMurmur364     = ":murmur364:"
	TypeBloomFilter   = ":bloomFilter:"
	TypeStandard      = ":standard:"
	TypeKM1           = ":km1:"
	TypeKM2           = ":km2:"
	TypeKSRains       = ":rains:"

	indent4  = "    "
	indent8  = indent4 + indent4
	indent12 = indent8 + indent4
)

func init() {
	/*h := log.CallerFileHandler(log.StdoutHandler)
	log.Root().SetHandler(h)*/
}

//ZoneFileParser is the interface for all parsers of zone files for RAINS
type ZoneFileParser interface {
	//Decode takes as input a byte string of section(s) in zonefile format. It returns a slice of
	//all contained assertions, shards, and zones in the provided order or an error in case of
	//failure.
	Decode(zoneFile []byte) ([]sections.MessageSectionWithSigForward, error)

	//DecodeZone takes as input a byte string of one zone in zonefile format. It returns the zone
	//exactly as it is in the zonefile or an error in case of failure.
	DecodeZone(zoneFile []byte) (*sections.ZoneSection, error)

	//Encode returns the given section represented in zone file format if it is an assertion, shard,
	//or zone. In all other cases it returns the section in a displayable format similar to the zone
	//file format
	Encode(section sections.MessageSection) string
}

//Parser can be used to parse RAINS zone files
type Parser struct{}

//Encode returns the given section represented in the zone file format if it is a zoneSection.
//In all other cases it returns the section in a displayable format similar to the zone file format
func (p Parser) Encode(s message.MessageSection) string {
	return GetEncoding(s, false)
}

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte) ([]section.MessageSectionWithSigForward, error) {
	log.Error("Not yet supported")
	return nil, nil
}

//DecodeZone returns a zone exactly as it is represented in the zonefile
func (p Parser) DecodeZone(zoneFile []byte) (*section.ZoneSection, error) {
	lines := removeComments(bufio.NewScanner(bytes.NewReader(zoneFile)))
	log.Debug("Preprocessed input", "data", lines)
	parser := ZFPNewParser()
	parser.Parse(&ZFPLex{lines: lines})
	zone, ok := parser.Result()[0].(*section.ZoneSection)
	if !ok {
		return nil, errors.New("First element of zonefile is not a zone. (Note, only the first element of the zonefile is considered)")
	}
	return zone, nil
}

//EncodeMessage transforms the given msg into a signable format.
//It must have already been verified that the msg does not contain malicious content.
//Signature meta data is not added
func (p Parser) EncodeMessage(msg *message.RainsMessage) []byte {
	encoding := encodeMessage(msg)
	return []byte(replaceWhitespaces(encoding))
}

//EncodeSection transforms the given msg into a signable format
//It must have already been verified that the section does not contain malicious content
//Signature meta data is not added
func (p Parser) EncodeSection(s section.MessageSectionWithSig) []byte {
	encoding := GetEncoding(s, true)
	return []byte(replaceWhitespaces(encoding))
}

//GetEncoding returns an encoding in zonefile format
func GetEncoding(s message.MessageSection, forSigning bool) string {
	encoding := ""
	switch s := s.(type) {
	case *section.AssertionSection:
		encoding = encodeAssertion(s, s.Context, s.SubjectZone, "", forSigning)
	case *section.ShardSection:
		encoding = encodeShard(s, s.Context, s.SubjectZone, "", forSigning)
	case *section.ZoneSection:
		encoding = encodeZone(s, forSigning)
	case *section.QuerySection:
		encoding = encodeQuery(s)
	case *section.NotificationSection:
		encoding = encodeNotification(s)
	case *section.AddressAssertionSection:
		encoding = encodeAddressAssertion(s)
	case *section.AddressQuerySection:
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
