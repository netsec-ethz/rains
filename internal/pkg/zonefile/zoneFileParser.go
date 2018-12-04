package zonefile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
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

//ZoneFileParser is the interface for all parsers of zone files for RAINS
type ZoneFileParser interface {
	//Decode takes as input a byte string of section(s) in zonefile format. It returns a slice of
	//all contained assertions, shards, and zones in the provided order or an error in case of
	//failure.
	Decode(zoneFile []byte) ([]section.WithSigForward, error)

	//DecodeZone takes as input a byte string of one zone in zonefile format. It returns the zone
	//exactly as it is in the zonefile or an error in case of failure.
	DecodeZone(zoneFile []byte) (*section.Zone, error)

	//DecodeNameQueriesUnsafe takes as input a byte string of name queries encoded in a format
	//resembling the zone file format. It returns the queries. It panics when the input format is
	//incorrect.
	DecodeNameQueriesUnsafe(encoding []byte) []*query.Name

	//LoadZone takes as input a path to a file containing a zone in zonefile
	//format. It returns the zone exactly as it is in the zonefile or an error
	//in case of failure.
	LoadZone(path string) (*section.Zone, error)

	//Encode returns the given section represented in zone file format if it is an assertion, shard,
	//or zone. In all other cases it returns the section in a displayable format similar to the zone
	//file format
	Encode(section section.Section) string

	//EncodeAndStore stores the given section represented in zone file format if
	//it is an assertion, shard, pshard, or zone. In all other cases it stores
	//the section in a displayable format similar to the zone file format
	EncodeAndStore(path string, section section.Section) error
}

//Parser can be used to parse RAINS zone files
type Parser struct{}

//Decode returns all assertions contained in the given zonefile
func (p Parser) Decode(zoneFile []byte) ([]section.WithSigForward, error) {
	lines := removeComments(bufio.NewScanner(bytes.NewReader(zoneFile)))
	log.Debug("Preprocessed input", "data", lines)
	parser := ZFPNewParser()
	parser.Parse(&ZFPLex{lines: lines})
	if len(parser.Result()) == 0 {
		return nil, errors.New("zonefile malformed. Was not able to parse it.")
	}
	return parser.Result(), nil
}

//DecodeZone returns a zone exactly as it is represented in the zonefile
func (p Parser) DecodeZone(zoneFile []byte) (*section.Zone, error) {
	lines := removeComments(bufio.NewScanner(bytes.NewReader(zoneFile)))
	log.Debug("Preprocessed input", "data", lines)
	parser := ZFPNewParser()
	parser.Parse(&ZFPLex{lines: lines})
	if len(parser.Result()) == 0 {
		return nil, errors.New("zonefile malformed. Was not able to parse it.")
	}
	zone, ok := parser.Result()[0].(*section.Zone)
	if !ok {
		return nil, errors.New("First element of zonefile is not a zone. (Note, only the first element of the zonefile is considered)")
	}
	return zone, nil
}

//DecodeNameQueriesUnsafe takes as input a byte string of name queries encoded in a format
//resembling the zone file format. It returns the queries. It panics when the input format is
//incorrect.
func (p Parser) DecodeNameQueriesUnsafe(encoding []byte) []*query.Name {
	queries := []*query.Name{}
	scanner := bufio.NewScanner(bytes.NewReader(encoding))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		queries = append(queries, decodeNameQueryUnsafe(scanner))
	}
	return queries
}

//LoadZone takes as input a path to a file containing a zone in zonefile format.
//It returns the zone exactly as it is in the zonefile or an error in case of
//failure.
func (p Parser) LoadZone(path string) (*section.Zone, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return p.DecodeZone(data)
}

//Encode returns the given section represented in the zone file format if it is a zoneSection.
//In all other cases it returns the section in a displayable format similar to the zone file format
func (p Parser) Encode(s section.Section) string {
	return GetEncoding(s, false)
}

//EncodeAndStore stores the given section represented in zone file format if
//it is an assertion, shard, pshard, or zone. In all other cases it stores
//the section in a displayable format similar to the zone file format
func (p Parser) EncodeAndStore(path string, section section.Section) error {
	encoding := p.Encode(section)
	return ioutil.WriteFile(path, []byte(encoding), 0600)
}

//GetEncoding returns an encoding in zonefile format
func GetEncoding(s section.Section, forSigning bool) string {
	encoding := ""
	switch s := s.(type) {
	case *section.Assertion:
		encoding = encodeAssertion(s, s.Context, s.SubjectZone, "", forSigning)
	case *section.Shard:
		encoding = encodeShard(s, s.Context, s.SubjectZone, "", forSigning)
	case *section.Zone:
		encoding = encodeZone(s, forSigning)
	case *query.Name:
		encoding = encodeQuery(s)
	case *section.Notification:
		encoding = encodeNotification(s)
	case *section.AddrAssertion:
		encoding = encodeAddressAssertion(s)
	case *query.Address:
		encoding = encodeAddressQuery(s)
	default:
		log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
		return ""
	}
	return encoding
}
