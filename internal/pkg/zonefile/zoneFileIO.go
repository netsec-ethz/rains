package zonefile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

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
	TypeShake256      = ":shake256:"
	TypeFnv64         = ":fnv64:"
	TypeFnv128        = ":fnv128:"
	TypeKM12          = ":bloomKM12:"
	TypeKM16          = ":bloomKM16:"
	TypeKM20          = ":bloomKM20:"
	TypeKM24          = ":bloomKM24:"
	TypeKSRains       = ":rains:"

	indent4  = "    "
	indent8  = indent4 + indent4
	indent12 = indent8 + indent4
)

//ZoneFileIO is the interface for all parsers of zone files for RAINS
type ZoneFileIO interface {
	//Decode takes as input a byte string of section(s) in zonefile format. It returns a slice of
	//all contained assertions, shards, and zones in the provided order or an error in case of
	//failure.
	Decode(zoneFile []byte) ([]section.WithSigForward, error)

	//DecodeNameQueriesUnsafe takes as input a byte string of name queries encoded in a format
	//resembling the zone file format. It returns the queries. It panics when the input format is
	//incorrect.
	DecodeNameQueriesUnsafe(encoding []byte) []*query.Name

	//LoadZonefile takes as input a path to a file containing a zone in zonefile
	//format. It returns the zone exactly as it is in the zonefile or an error
	//in case of failure.
	LoadZonefile(path string) ([]section.WithSigForward, error)

	//Encode returns the given sections represented in zone file format if it is an assertion,
	//shard, or zone. In all other cases it returns the sections in a displayable format similar to
	//the zonefile format
	Encode(sections []section.Section) string

	//EncodeSection returns the given section represented in zone file format if it is an assertion,
	//shard, or zone. In all other cases it returns the section in a displayable format similar to
	//the zonefile format
	EncodeSection(section section.Section) string

	//EncodeAndStore stores the given sections represented in zone file format if it is an
	//assertion, shard, pshard, or zone. In all other cases it stores the sections in a displayable
	//format similar to the zone file format
	EncodeAndStore(path string, section []section.Section) error
}

//Parser can be used to parse and encode RAINS zone files
type IO struct{}

//Decode returns all assertions contained in the given zonefile
func (p IO) Decode(zoneFile []byte) ([]section.WithSigForward, error) {
	lines := removeComments(bufio.NewScanner(bytes.NewReader(zoneFile)))
	log.Debug("Preprocessed input", "data", lines)
	parser := ZFPNewParser()
	parser.Parse(&ZFPLex{lines: lines})
	if len(parser.Result()) == 0 {
		return nil, errors.New("zonefile malformed. Was not able to parse it.")
	}
	return parser.Result(), nil
}

//DecodeNameQueriesUnsafe takes as input a byte string of name queries encoded in a format
//resembling the zone file format. It returns the queries. It panics when the input format is
//incorrect.
func (p IO) DecodeNameQueriesUnsafe(encoding []byte) []*query.Name {
	queries := []*query.Name{}
	scanner := bufio.NewScanner(bytes.NewReader(encoding))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		queries = append(queries, decodeNameQueryUnsafe(scanner))
	}
	return queries
}

//LoadZonefile takes as input a path to a file containing a zone in zonefile format. It returns the zone
//exactly as it is in the zonefile or an error in case of failure.
func (p IO) LoadZonefile(path string) ([]section.WithSigForward, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return p.Decode(data)
}

//Encode returns the given sections represented in the zone file format if it is a zoneSection.
//In all other cases it returns the sections in a displayable format similar to the zone file format
func (p IO) Encode(sections []section.Section) string {
	var encodings []string
	for _, s := range sections {
		encodings = append(encodings, GetEncoding(s, false))
	}
	return strings.Join(encodings, "\n")
}

//EncodeSection returns the given section represented in the zone file format if it is a zoneSection.
//In all other cases it returns the section in a displayable format similar to the zone file format
func (p IO) EncodeSection(section section.Section) string {
	return GetEncoding(section, false)
}

//EncodeAndStore stores the given section represented in zone file format if
//it is an assertion, shard, pshard, or zone. In all other cases it stores
//the section in a displayable format similar to the zone file format
func (p IO) EncodeAndStore(path string, sections []section.Section) error {
	encoding := p.Encode(sections)
	return ioutil.WriteFile(path, []byte(encoding), 0600)
}

//GetEncoding returns an encoding in zonefile format
func GetEncoding(s section.Section, forSigning bool) string {
	encoding := ""
	switch s := s.(type) {
	case *section.Assertion:
		encoding = encodeAssertion(s, s.Context, s.SubjectZone, "", forSigning)
	case *section.Shard:
		encoding = encodeShard(s, s.Context, s.SubjectZone, "")
	case *section.Pshard:
		encoding = encodePshard(s, s.Context, s.SubjectZone, "")
	case *section.Zone:
		encoding = encodeZone(s)
	case *query.Name:
		encoding = encodeQuery(s)
	case *section.Notification:
		encoding = encodeNotification(s)
	default:
		log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
		return ""
	}
	return encoding
}
