//line zonefileParser.y:8
package zonefile

import __yyfmt__ "fmt"

//line zonefileParser.y:9
import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"

	"io/ioutil"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
)

//AddSigs adds signatures to section
func AddSigs(sec section.WithSigForward, signatures []signature.Sig) {
	for _, sig := range signatures {
		sec.AddSig(sig)
	}
}

func DecodeBloomFilter(hashAlgos []algorithmTypes.Hash, modeOfOperation section.ModeOfOperationType,
	nofHashFunctions, filter string) (section.BloomFilter, error) {
	funcs, err := strconv.Atoi(nofHashFunctions)
	if err != nil {
		return section.BloomFilter{}, errors.New("nofHashFunctions is not a number")
	}
	decodedFilter, err := hex.DecodeString(filter)
	if err != nil {
		return section.BloomFilter{}, err
	}
	return section.BloomFilter{
		HashFamily:       hashAlgos,
		NofHashFunctions: funcs,
		ModeOfOperation:  modeOfOperation,
		Filter:           bitarray.BitArray(decodedFilter),
	}, nil
}

func DecodePublicKeyID(keyphase string) (keys.PublicKeyID, error) {
	phase, err := strconv.Atoi(keyphase)
	if err != nil {
		return keys.PublicKeyID{}, errors.New("keyphase is not a number")
	}
	return keys.PublicKeyID{
		Algorithm: algorithmTypes.Ed25519,
		KeyPhase:  phase,
		KeySpace:  keys.RainsKeySpace,
	}, nil
}

func DecodeEd25519SignatureData(input string) (interface{}, error) {
	return "notYetImplemented", nil
}

// DecodeEd25519PublicKeyData returns the publicKey or an error in case
// pkeyInput is malformed i.e. it is not in zone file format.
func DecodeEd25519PublicKeyData(pkeyInput string, keyphase string) (keys.PublicKey, error) {
	publicKeyID, err := DecodePublicKeyID(keyphase)
	if err != nil {
		return keys.PublicKey{}, err
	}
	pKey, err := hex.DecodeString(pkeyInput)
	if err != nil {
		return keys.PublicKey{}, err
	}
	if len(pKey) == 32 {
		publicKey := keys.PublicKey{Key: ed25519.PublicKey(pKey), PublicKeyID: publicKeyID}
		return publicKey, nil
	}
	return keys.PublicKey{}, fmt.Errorf("wrong public key length: got %d, want: 32", len(pKey))
}

func DecodeCertificate(ptype object.ProtocolType, usage object.CertificateUsage,
	hashAlgo algorithmTypes.Hash, certificat string) (object.Certificate,
	error) {
	data, err := hex.DecodeString(certificat)
	if err != nil {
		return object.Certificate{}, err
	}
	return object.Certificate{
		Type:     ptype,
		Usage:    usage,
		HashAlgo: hashAlgo,
		Data:     data,
	}, nil
}

func DecodeSrv(name, portString, priorityString string) (object.ServiceInfo, error) {
	port, err := strconv.Atoi(portString)
	if err != nil || port < 0 || port > 65535 {
		return object.ServiceInfo{}, errors.New("Port is not a number or out of range")
	}
	priority, err := strconv.Atoi(priorityString)
	if err != nil || port < 0 {
		return object.ServiceInfo{}, errors.New("Priority is not a number or negative")
	}
	return object.ServiceInfo{
		Name:     name,
		Port:     uint16(port),
		Priority: uint(priority),
	}, nil
}

func DecodeValidity(validSince, validUntil string) (int64, int64, error) {
	vsince, err := strconv.ParseInt(validSince, 10, 64)
	if err != nil || vsince < 0 {
		return 0, 0, errors.New("validSince is not a number or negative")
	}
	vuntil, err := strconv.ParseInt(validUntil, 10, 64)
	if err != nil || vuntil < 0 {
		return 0, 0, errors.New("validUntil is not a number or negative")
	}
	return vsince, vuntil, nil
}

//Result gets stored in this variable
var output []section.WithSigForward

//line zonefileParser.y:141
type ZFPSymType struct {
	yys           int
	str           string
	assertion     *section.Assertion
	assertions    []*section.Assertion
	shard         *section.Shard
	pshard        *section.Pshard
	zone          *section.Zone
	sections      []section.WithSigForward
	objects       []object.Object
	object        object.Object
	objectTypes   []object.Type
	objectType    object.Type
	signatures    []signature.Sig
	signature     signature.Sig
	shardRange    []string
	publicKey     keys.PublicKey
	protocolType  object.ProtocolType
	certUsage     object.CertificateUsage
	hashType      algorithmTypes.Hash
	hashTypes     []algorithmTypes.Hash
	dataStructure section.DataStructure
	bfOpMode      section.ModeOfOperationType
}

const ID = 57346
const assertionType = 57347
const shardType = 57348
const pshardType = 57349
const zoneType = 57350
const nameType = 57351
const ip4Type = 57352
const ip6Type = 57353
const redirType = 57354
const delegType = 57355
const namesetType = 57356
const certType = 57357
const srvType = 57358
const regrType = 57359
const regtType = 57360
const infraType = 57361
const extraType = 57362
const nextType = 57363
const sigType = 57364
const ed25519Type = 57365
const unspecified = 57366
const tls = 57367
const trustAnchor = 57368
const endEntity = 57369
const noHash = 57370
const sha256 = 57371
const sha384 = 57372
const sha512 = 57373
const fnv64 = 57374
const murmur364 = 57375
const bloomFilterType = 57376
const standard = 57377
const km1 = 57378
const km2 = 57379
const rains = 57380
const rangeBegin = 57381
const rangeEnd = 57382
const lBracket = 57383
const rBracket = 57384
const lParenthesis = 57385
const rParenthesis = 57386

var ZFPToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"ID",
	"assertionType",
	"shardType",
	"pshardType",
	"zoneType",
	"nameType",
	"ip4Type",
	"ip6Type",
	"redirType",
	"delegType",
	"namesetType",
	"certType",
	"srvType",
	"regrType",
	"regtType",
	"infraType",
	"extraType",
	"nextType",
	"sigType",
	"ed25519Type",
	"unspecified",
	"tls",
	"trustAnchor",
	"endEntity",
	"noHash",
	"sha256",
	"sha384",
	"sha512",
	"fnv64",
	"murmur364",
	"bloomFilterType",
	"standard",
	"km1",
	"km2",
	"rains",
	"rangeBegin",
	"rangeEnd",
	"lBracket",
	"rBracket",
	"lParenthesis",
	"rParenthesis",
}
var ZFPStatenames = [...]string{}

const ZFPEofCode = 1
const ZFPErrCode = 2
const ZFPInitialStackSize = 16

//line zonefileParser.y:835

/*  Lexer  */

// The parser expects the lexer to return 0 on EOF.
const eof = 0

type ZFPLex struct {
	lines   [][]string
	lineNr  int
	linePos int
}

func (l *ZFPLex) Lex(lval *ZFPSymType) int {
	if l.lineNr == len(l.lines) {
		return eof
	}
	//read data and skip empty lines
	line := l.lines[l.lineNr]
	for len(line) == 0 {
		l.lineNr++
		if l.lineNr == len(l.lines) {
			return eof
		}
		line = l.lines[l.lineNr]
	}
	word := line[l.linePos]
	//update state
	if l.linePos == len(line)-1 {
		l.lineNr++
		l.linePos = 0
	} else {
		l.linePos++
	}
	//return token
	switch word {
	case TypeAssertion:
		return assertionType
	case TypeShard:
		return shardType
	case TypePshard:
		return pshardType
	case TypeZone:
		return zoneType
	case TypeName:
		return nameType
	case TypeIP6:
		return ip6Type
	case TypeIP4:
		return ip4Type
	case TypeRedirection:
		return redirType
	case TypeDelegation:
		return delegType
	case TypeNameSet:
		return namesetType
	case TypeCertificate:
		return certType
	case TypeServiceInfo:
		return srvType
	case TypeRegistrar:
		return regrType
	case TypeRegistrant:
		return regtType
	case TypeInfraKey:
		return infraType
	case TypeExternalKey:
		return extraType
	case TypeNextKey:
		return nextType
	case TypeSignature:
		return sigType
	case TypeEd25519:
		return ed25519Type
	case TypeUnspecified:
		return unspecified
	case TypePTTLS:
		return tls
	case TypeCUTrustAnchor:
		return trustAnchor
	case TypeCUEndEntity:
		return endEntity
	case TypeNoHash:
		return noHash
	case TypeSha256:
		return sha256
	case TypeSha384:
		return sha384
	case TypeSha512:
		return sha512
	case TypeFnv64:
		return fnv64
	case TypeMurmur364:
		return murmur364
	case TypeBloomFilter:
		return bloomFilterType
	case TypeStandard:
		return standard
	case TypeKM1:
		return km1
	case TypeKM2:
		return km2
	case TypeKSRains:
		return rains
	case "<":
		return rangeBegin
	case ">":
		return rangeEnd
	case "[":
		return lBracket
	case "]":
		return rBracket
	case "(":
		return lParenthesis
	case ")":
		return rParenthesis
	default:
		lval.str = word
		return ID
	}
}

// The parser calls this method on a parse error.
func (l *ZFPLex) Error(s string) {
	for l.linePos == 0 && l.lineNr > 0 {
		l.lineNr--
		l.linePos = len(l.lines[l.lineNr])
	}
	if l.linePos == 0 && l.lineNr == 0 {
		log.Error("syntax error:", "lineNr", 1, "wordNr", 0,
			"token", "noToken")
	} else {
		log.Error("syntax error:", "lineNr", l.lineNr+1, "wordNr", l.linePos,
			"token", l.lines[l.lineNr][l.linePos-1])
	}
}

func main() {
	file, err := ioutil.ReadFile("zonefile.txt")
	if err != nil {
		log.Error(err.Error())
		return
	}
	lines := removeComments(bufio.NewScanner(bytes.NewReader(file)))
	log.Debug("Preprocessed input", "data", lines)
	ZFPParse(&ZFPLex{lines: lines})
}

func removeComments(scanner *bufio.Scanner) [][]string {
	var lines [][]string
	for scanner.Scan() {
		inputWithoutComments := strings.Split(scanner.Text(), ";")[0]
		var words []string
		ws := bufio.NewScanner(strings.NewReader(inputWithoutComments))
		ws.Split(bufio.ScanWords)
		for ws.Scan() {
			words = append(words, ws.Text())
		}
		lines = append(lines, words)
	}
	return lines
}

//line yacctab:1
var ZFPExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
}

const ZFPPrivate = 57344

const ZFPLast = 236

var ZFPAct = [...]int{

	161, 132, 129, 5, 4, 3, 47, 90, 39, 114,
	73, 71, 72, 68, 66, 70, 63, 69, 162, 163,
	164, 165, 166, 167, 168, 169, 170, 171, 172, 173,
	174, 67, 65, 62, 16, 64, 30, 181, 11, 61,
	133, 134, 135, 136, 137, 138, 95, 11, 12, 13,
	124, 185, 11, 32, 153, 127, 141, 126, 43, 125,
	93, 92, 38, 36, 35, 33, 94, 98, 101, 103,
	106, 108, 107, 105, 104, 182, 89, 24, 21, 41,
	22, 145, 146, 97, 155, 100, 102, 99, 96, 128,
	31, 34, 120, 121, 25, 190, 191, 192, 34, 37,
	130, 34, 28, 133, 134, 135, 136, 137, 138, 117,
	118, 23, 23, 23, 88, 123, 122, 113, 46, 91,
	30, 86, 85, 84, 83, 82, 81, 80, 79, 78,
	44, 77, 151, 154, 152, 75, 11, 12, 13, 14,
	76, 74, 156, 158, 157, 194, 176, 162, 163, 164,
	165, 166, 167, 168, 169, 170, 171, 172, 173, 174,
	193, 186, 74, 76, 75, 77, 78, 79, 80, 81,
	82, 83, 84, 85, 86, 15, 188, 187, 184, 183,
	180, 179, 178, 177, 17, 18, 19, 175, 159, 150,
	149, 148, 143, 147, 142, 140, 115, 119, 112, 111,
	110, 109, 87, 45, 42, 26, 20, 1, 189, 131,
	144, 116, 29, 27, 160, 60, 59, 58, 57, 56,
	55, 54, 53, 52, 51, 49, 50, 48, 7, 40,
	9, 8, 2, 139, 10, 6,
}
var ZFPPact = [...]int{

	-1000, -1000, 131, -1000, -1000, -1000, -1000, -9, -9, -9,
	-9, 202, 74, 73, 201, -1000, 98, -1000, -1000, -1000,
	49, 61, 23, 59, 58, 45, 200, 14, -1000, 199,
	95, 153, 198, 72, -1000, -1000, -1000, -1000, 72, -1000,
	-1000, 20, 19, -1000, -1000, -1000, 28, 4, 132, 124,
	130, 119, 116, 114, 112, 110, 108, 106, 104, 102,
	100, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, 197, 196, 195, 194, 94, 192,
	85, 193, 192, 192, 93, 92, 27, 18, 16, 51,
	47, 45, 75, -1000, 191, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, 15,
	-1000, -1000, -1000, 190, 188, -1000, 55, -1000, -1000, 189,
	188, 188, 187, 186, 185, 153, -1000, -1000, -1000, -1000,
	-1000, 12, -1000, -1000, -1000, -1000, -1000, -1000, -1000, 42,
	184, 138, 183, -1000, 75, -1000, -1000, 179, 178, 177,
	176, -5, 33, 175, -1000, -1000, -1000, -1000, -1000, 174,
	9, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, 173, -1000, -1000, -1000,
	172, -1000, -1000, 60, -1000, -1000, -1000, -1000, 156, 141,
	-1000, -1000, -1000, -1000, -1000,
}
var ZFPPgo = [...]int{

	0, 235, 234, 233, 232, 4, 231, 80, 3, 230,
	8, 229, 7, 2, 228, 6, 227, 226, 225, 224,
	223, 222, 221, 220, 219, 218, 217, 216, 215, 39,
	16, 33, 35, 32, 14, 31, 13, 17, 15, 11,
	12, 10, 214, 0, 175, 213, 102, 212, 9, 211,
	210, 209, 1, 208, 207,
}
var ZFPR1 = [...]int{

	0, 54, 4, 4, 4, 4, 4, 1, 1, 2,
	3, 3, 3, 3, 5, 5, 6, 6, 7, 7,
	7, 7, 12, 12, 8, 8, 9, 9, 10, 11,
	51, 51, 53, 53, 53, 13, 13, 14, 14, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 16, 16, 29, 42, 42, 43, 43, 43,
	43, 43, 43, 43, 43, 43, 43, 43, 43, 43,
	18, 18, 31, 17, 17, 30, 19, 19, 32, 20,
	20, 33, 21, 21, 34, 22, 22, 35, 23, 23,
	36, 24, 24, 37, 25, 25, 38, 26, 26, 39,
	27, 27, 40, 28, 28, 41, 49, 49, 50, 50,
	52, 52, 52, 52, 52, 52, 48, 48, 44, 45,
	45, 46, 46, 47,
}
var ZFPR2 = [...]int{

	0, 1, 0, 2, 2, 2, 2, 1, 2, 6,
	0, 2, 2, 2, 1, 2, 7, 5, 2, 2,
	2, 2, 0, 2, 1, 2, 5, 3, 1, 7,
	1, 2, 1, 1, 1, 1, 2, 5, 7, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 2, 5, 1, 2, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 2, 2, 1, 2, 2, 1, 2, 2, 1,
	2, 4, 1, 2, 2, 1, 2, 5, 1, 2,
	4, 1, 2, 2, 1, 2, 2, 1, 2, 4,
	1, 2, 4, 1, 2, 6, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 2, 3, 1,
	2, 1, 2, 6,
}
var ZFPChk = [...]int{

	-1000, -54, -4, -13, -5, -8, -1, -14, -6, -9,
	-2, 5, 6, 7, 8, -44, 43, -44, -44, -44,
	4, 4, -7, 39, 4, -7, 4, -45, -46, -47,
	22, 41, 4, 4, 40, 41, 4, 40, 4, -10,
	-11, 34, 4, 44, -46, 4, 23, -15, -16, -18,
	-17, -19, -20, -21, -22, -23, -24, -25, -26, -27,
	-28, -29, -31, -30, -32, -33, -34, -35, -36, -37,
	-38, -39, -40, -41, 9, 11, 10, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 4, -7, 4,
	-12, -7, 41, 41, 38, 42, -29, -31, -30, -32,
	-33, -34, -35, -36, -37, -38, -39, -40, -41, 4,
	4, 4, 4, 23, -48, 4, -49, 24, 25, 4,
	-48, -48, 23, 23, 23, 41, 41, 4, 42, -13,
	-10, -51, -52, 28, 29, 30, 31, 32, 33, -3,
	4, 41, 4, 4, -50, 26, 27, 4, 4, 4,
	4, -15, -12, 42, -52, 42, -13, -5, -8, 4,
	-42, -43, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 4, -52, 4, 4, 4,
	4, 42, 42, 4, 4, 42, -43, 4, 4, -53,
	35, 36, 37, 4, 4,
}
var ZFPDef = [...]int{

	2, -2, 1, 3, 4, 5, 6, 35, 14, 24,
	7, 0, 0, 0, 0, 36, 0, 15, 25, 8,
	0, 0, 0, 0, 0, 0, 0, 0, 119, 121,
	0, 0, 0, 18, 20, 22, 19, 21, 18, 27,
	28, 0, 0, 118, 120, 122, 0, 0, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 70, 73, 76, 79, 82, 85, 88, 91,
	94, 97, 100, 103, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 10, 0, 37, 53, 71, 74, 77,
	80, 83, 86, 89, 92, 95, 98, 101, 104, 0,
	72, 75, 78, 0, 84, 116, 0, 106, 107, 0,
	93, 96, 0, 0, 0, 0, 22, 18, 17, 23,
	26, 0, 30, 110, 111, 112, 113, 114, 115, 0,
	0, 0, 0, 117, 0, 108, 109, 0, 0, 0,
	0, 0, 0, 0, 31, 9, 11, 12, 13, 0,
	0, 55, 57, 58, 59, 60, 61, 62, 63, 64,
	65, 66, 67, 68, 69, 81, 0, 90, 99, 102,
	0, 38, 16, 0, 123, 54, 56, 87, 0, 0,
	32, 33, 34, 105, 29,
}
var ZFPTok1 = [...]int{

	1,
}
var ZFPTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44,
}
var ZFPTok3 = [...]int{
	0,
}

var ZFPErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	ZFPDebug        = 0
	ZFPErrorVerbose = false
)

type ZFPLexer interface {
	Lex(lval *ZFPSymType) int
	Error(s string)
}

type ZFPParser interface {
	Parse(ZFPLexer) int
	Lookahead() int
	Result() []section.WithSigForward
}

type ZFPParserImpl struct {
	lval  ZFPSymType
	stack [ZFPInitialStackSize]ZFPSymType
	char  int
}

func (p *ZFPParserImpl) Lookahead() int {
	return p.char
}

func (p *ZFPParserImpl) Result() []section.WithSigForward {
	return output
}
func ZFPNewParser() ZFPParser {
	return &ZFPParserImpl{}
}

const ZFPFlag = -1000

func ZFPTokname(c int) string {
	if c >= 1 && c-1 < len(ZFPToknames) {
		if ZFPToknames[c-1] != "" {
			return ZFPToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func ZFPStatname(s int) string {
	if s >= 0 && s < len(ZFPStatenames) {
		if ZFPStatenames[s] != "" {
			return ZFPStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func ZFPErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !ZFPErrorVerbose {
		return "syntax error"
	}

	for _, e := range ZFPErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + ZFPTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := ZFPPact[state]
	for tok := TOKSTART; tok-1 < len(ZFPToknames); tok++ {
		if n := base + tok; n >= 0 && n < ZFPLast && ZFPChk[ZFPAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if ZFPDef[state] == -2 {
		i := 0
		for ZFPExca[i] != -1 || ZFPExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; ZFPExca[i] >= 0; i += 2 {
			tok := ZFPExca[i]
			if tok < TOKSTART || ZFPExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if ZFPExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += ZFPTokname(tok)
	}
	return res
}

func ZFPlex1(lex ZFPLexer, lval *ZFPSymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = ZFPTok1[0]
		goto out
	}
	if char < len(ZFPTok1) {
		token = ZFPTok1[char]
		goto out
	}
	if char >= ZFPPrivate {
		if char < ZFPPrivate+len(ZFPTok2) {
			token = ZFPTok2[char-ZFPPrivate]
			goto out
		}
	}
	for i := 0; i < len(ZFPTok3); i += 2 {
		token = ZFPTok3[i+0]
		if token == char {
			token = ZFPTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = ZFPTok2[1] /* unknown char */
	}
	if ZFPDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", ZFPTokname(token), uint(char))
	}
	return char, token
}

func ZFPParse(ZFPlex ZFPLexer) int {
	return ZFPNewParser().Parse(ZFPlex)
}

func (ZFPrcvr *ZFPParserImpl) Parse(ZFPlex ZFPLexer) int {
	var ZFPn int
	var ZFPVAL ZFPSymType
	var ZFPDollar []ZFPSymType
	_ = ZFPDollar // silence set and not used
	ZFPS := ZFPrcvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	ZFPstate := 0
	ZFPrcvr.char = -1
	ZFPtoken := -1 // ZFPrcvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		ZFPstate = -1
		ZFPrcvr.char = -1
		ZFPtoken = -1
	}()
	ZFPp := -1
	goto ZFPstack

ret0:
	return 0

ret1:
	return 1

ZFPstack:
	/* put a state and value onto the stack */
	if ZFPDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", ZFPTokname(ZFPtoken), ZFPStatname(ZFPstate))
	}

	ZFPp++
	if ZFPp >= len(ZFPS) {
		nyys := make([]ZFPSymType, len(ZFPS)*2)
		copy(nyys, ZFPS)
		ZFPS = nyys
	}
	ZFPS[ZFPp] = ZFPVAL
	ZFPS[ZFPp].yys = ZFPstate

ZFPnewstate:
	ZFPn = ZFPPact[ZFPstate]
	if ZFPn <= ZFPFlag {
		goto ZFPdefault /* simple state */
	}
	if ZFPrcvr.char < 0 {
		ZFPrcvr.char, ZFPtoken = ZFPlex1(ZFPlex, &ZFPrcvr.lval)
	}
	ZFPn += ZFPtoken
	if ZFPn < 0 || ZFPn >= ZFPLast {
		goto ZFPdefault
	}
	ZFPn = ZFPAct[ZFPn]
	if ZFPChk[ZFPn] == ZFPtoken { /* valid shift */
		ZFPrcvr.char = -1
		ZFPtoken = -1
		ZFPVAL = ZFPrcvr.lval
		ZFPstate = ZFPn
		if Errflag > 0 {
			Errflag--
		}
		goto ZFPstack
	}

ZFPdefault:
	/* default state action */
	ZFPn = ZFPDef[ZFPstate]
	if ZFPn == -2 {
		if ZFPrcvr.char < 0 {
			ZFPrcvr.char, ZFPtoken = ZFPlex1(ZFPlex, &ZFPrcvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if ZFPExca[xi+0] == -1 && ZFPExca[xi+1] == ZFPstate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			ZFPn = ZFPExca[xi+0]
			if ZFPn < 0 || ZFPn == ZFPtoken {
				break
			}
		}
		ZFPn = ZFPExca[xi+1]
		if ZFPn < 0 {
			goto ret0
		}
	}
	if ZFPn == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			ZFPlex.Error(ZFPErrorMessage(ZFPstate, ZFPtoken))
			Nerrs++
			if ZFPDebug >= 1 {
				__yyfmt__.Printf("%s", ZFPStatname(ZFPstate))
				__yyfmt__.Printf(" saw %s\n", ZFPTokname(ZFPtoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for ZFPp >= 0 {
				ZFPn = ZFPPact[ZFPS[ZFPp].yys] + ZFPErrCode
				if ZFPn >= 0 && ZFPn < ZFPLast {
					ZFPstate = ZFPAct[ZFPn] /* simulate a shift of "error" */
					if ZFPChk[ZFPstate] == ZFPErrCode {
						goto ZFPstack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if ZFPDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", ZFPS[ZFPp].yys)
				}
				ZFPp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if ZFPDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", ZFPTokname(ZFPtoken))
			}
			if ZFPtoken == ZFPEofCode {
				goto ret1
			}
			ZFPrcvr.char = -1
			ZFPtoken = -1
			goto ZFPnewstate /* try again in the same state */
		}
	}

	/* reduction by production ZFPn */
	if ZFPDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", ZFPn, ZFPStatname(ZFPstate))
	}

	ZFPnt := ZFPn
	ZFPpt := ZFPp
	_ = ZFPpt // guard against "declared and not used"

	ZFPp -= ZFPR2[ZFPn]
	// ZFPp is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if ZFPp+1 >= len(ZFPS) {
		nyys := make([]ZFPSymType, len(ZFPS)*2)
		copy(nyys, ZFPS)
		ZFPS = nyys
	}
	ZFPVAL = ZFPS[ZFPp+1]

	/* consult goto table to find next state */
	ZFPn = ZFPR1[ZFPn]
	ZFPg := ZFPPgo[ZFPn]
	ZFPj := ZFPg + ZFPS[ZFPp].yys + 1

	if ZFPj >= ZFPLast {
		ZFPstate = ZFPAct[ZFPg]
	} else {
		ZFPstate = ZFPAct[ZFPj]
		if ZFPChk[ZFPstate] != -ZFPn {
			ZFPstate = ZFPAct[ZFPg]
		}
	}
	// dummy call; replaced with literal code
	switch ZFPnt {

	case 1:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:219
		{
			output = ZFPDollar[1].sections
		}
	case 2:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:224
		{
			ZFPVAL.sections = nil
		}
	case 3:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:228
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].assertion)
		}
	case 4:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:232
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].shard)
		}
	case 5:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:236
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].pshard)
		}
	case 6:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:240
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].zone)
		}
	case 8:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:246
		{
			AddSigs(ZFPDollar[1].zone, ZFPDollar[2].signatures)
			ZFPVAL.zone = ZFPDollar[1].zone
		}
	case 9:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:252
		{
			ZFPVAL.zone = &section.Zone{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				Content:     ZFPDollar[5].sections,
			}
		}
	case 10:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:261
		{
			ZFPVAL.sections = nil
		}
	case 11:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:265
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].assertion)
		}
	case 12:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:269
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].shard)
		}
	case 13:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:273
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].pshard)
		}
	case 15:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:279
		{
			AddSigs(ZFPDollar[1].shard, ZFPDollar[2].signatures)
			ZFPVAL.shard = ZFPDollar[1].shard
		}
	case 16:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:285
		{
			ZFPVAL.shard = &section.Shard{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				RangeFrom:   ZFPDollar[4].shardRange[0],
				RangeTo:     ZFPDollar[4].shardRange[1],
				Content:     ZFPDollar[6].assertions,
			}
		}
	case 17:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:295
		{
			ZFPVAL.shard = &section.Shard{
				RangeFrom: ZFPDollar[2].shardRange[0],
				RangeTo:   ZFPDollar[2].shardRange[1],
				Content:   ZFPDollar[4].assertions,
			}
		}
	case 18:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:304
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ZFPDollar[2].str}
		}
	case 19:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:308
		{
			ZFPVAL.shardRange = []string{"<", ZFPDollar[2].str}
		}
	case 20:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:312
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ">"}
		}
	case 21:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:316
		{
			ZFPVAL.shardRange = []string{"<", ">"}
		}
	case 22:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:321
		{
			ZFPVAL.assertions = nil
		}
	case 23:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:325
		{
			ZFPVAL.assertions = append(ZFPDollar[1].assertions, ZFPDollar[2].assertion)
		}
	case 25:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:331
		{
			AddSigs(ZFPDollar[1].pshard, ZFPDollar[2].signatures)
			ZFPVAL.pshard = ZFPDollar[1].pshard
		}
	case 26:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:337
		{
			ZFPVAL.pshard = &section.Pshard{
				SubjectZone:   ZFPDollar[2].str,
				Context:       ZFPDollar[3].str,
				RangeFrom:     ZFPDollar[4].shardRange[0],
				RangeTo:       ZFPDollar[4].shardRange[1],
				Datastructure: ZFPDollar[5].dataStructure,
			}
		}
	case 27:
		ZFPDollar = ZFPS[ZFPpt-3 : ZFPpt+1]
		//line zonefileParser.y:347
		{
			ZFPVAL.pshard = &section.Pshard{
				RangeFrom:     ZFPDollar[2].shardRange[0],
				RangeTo:       ZFPDollar[2].shardRange[1],
				Datastructure: ZFPDollar[3].dataStructure,
			}
		}
	case 29:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:358
		{
			bloomFilter, err := DecodeBloomFilter(ZFPDollar[3].hashTypes, ZFPDollar[6].bfOpMode, ZFPDollar[5].str, ZFPDollar[7].str)
			if err != nil {
				log.Error("semantic error:", "DecodeBloomFilter", err)
			}
			ZFPVAL.dataStructure = section.DataStructure{
				Type: section.BloomFilterType,
				Data: bloomFilter,
			}
		}
	case 30:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:370
		{
			ZFPVAL.hashTypes = []algorithmTypes.Hash{ZFPDollar[1].hashType}
		}
	case 31:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:374
		{
			ZFPVAL.hashTypes = append(ZFPDollar[1].hashTypes, ZFPDollar[2].hashType)
		}
	case 32:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:379
		{
			ZFPVAL.bfOpMode = section.StandardOpType
		}
	case 33:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:383
		{
			ZFPVAL.bfOpMode = section.KirschMitzenmacher1
		}
	case 34:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:387
		{
			ZFPVAL.bfOpMode = section.KirschMitzenmacher2
		}
	case 36:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:393
		{
			AddSigs(ZFPDollar[1].assertion, ZFPDollar[2].signatures)
			ZFPVAL.assertion = ZFPDollar[1].assertion
		}
	case 37:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:399
		{
			ZFPVAL.assertion = &section.Assertion{
				SubjectName: ZFPDollar[2].str,
				Content:     ZFPDollar[4].objects,
			}
		}
	case 38:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:406
		{
			ZFPVAL.assertion = &section.Assertion{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				SubjectName: ZFPDollar[4].str,
				Content:     ZFPDollar[6].objects,
			}
		}
	case 52:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:430
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 53:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:434
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 54:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:439
		{
			ZFPVAL.object = object.Object{
				Type: object.OTName,
				Value: object.Name{
					Name:  ZFPDollar[2].str,
					Types: ZFPDollar[4].objectTypes,
				},
			}
		}
	case 55:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:450
		{
			ZFPVAL.objectTypes = []object.Type{ZFPDollar[1].objectType}
		}
	case 56:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:454
		{
			ZFPVAL.objectTypes = append(ZFPDollar[1].objectTypes, ZFPDollar[2].objectType)
		}
	case 57:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:459
		{
			ZFPVAL.objectType = object.OTName
		}
	case 58:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:463
		{
			ZFPVAL.objectType = object.OTIP4Addr
		}
	case 59:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:467
		{
			ZFPVAL.objectType = object.OTIP6Addr
		}
	case 60:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:471
		{
			ZFPVAL.objectType = object.OTRedirection
		}
	case 61:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:475
		{
			ZFPVAL.objectType = object.OTDelegation
		}
	case 62:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:479
		{
			ZFPVAL.objectType = object.OTNameset
		}
	case 63:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:483
		{
			ZFPVAL.objectType = object.OTCertInfo
		}
	case 64:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:487
		{
			ZFPVAL.objectType = object.OTServiceInfo
		}
	case 65:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:491
		{
			ZFPVAL.objectType = object.OTRegistrar
		}
	case 66:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:495
		{
			ZFPVAL.objectType = object.OTRegistrant
		}
	case 67:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:499
		{
			ZFPVAL.objectType = object.OTInfraKey
		}
	case 68:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:503
		{
			ZFPVAL.objectType = object.OTExtraKey
		}
	case 69:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:507
		{
			ZFPVAL.objectType = object.OTNextKey
		}
	case 70:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:512
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 71:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:516
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 72:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:521
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTIP6Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 73:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:529
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 74:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:533
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 75:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:538
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTIP4Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 76:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:546
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 77:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:550
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 78:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:555
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRedirection,
				Value: ZFPDollar[2].str,
			}
		}
	case 79:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:563
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 80:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:567
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 81:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:572
		{
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			ZFPVAL.object = object.Object{
				Type:  object.OTDelegation,
				Value: pkey,
			}
		}
	case 82:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:584
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 83:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:588
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 84:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:593
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTNameset,
				Value: ZFPDollar[2].str,
			}
		}
	case 85:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:601
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 86:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:605
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 87:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:610
		{
			cert, err := DecodeCertificate(ZFPDollar[2].protocolType, ZFPDollar[3].certUsage, ZFPDollar[4].hashType, ZFPDollar[5].str)
			if err != nil {
				log.Error("semantic error:", "Decode certificate", err)
			}
			ZFPVAL.object = object.Object{
				Type:  object.OTCertInfo,
				Value: cert,
			}
		}
	case 88:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:622
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 89:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:626
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 90:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:631
		{
			srv, err := DecodeSrv(ZFPDollar[2].str, ZFPDollar[3].str, ZFPDollar[4].str)
			if err != nil {
				log.Error("semantic error:", "error", err)
			}
			ZFPVAL.object = object.Object{
				Type:  object.OTServiceInfo,
				Value: srv,
			}
		}
	case 91:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:643
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 92:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:647
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 93:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:652
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRegistrar,
				Value: ZFPDollar[2].str,
			}
		}
	case 94:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:660
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 95:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:664
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 96:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:669
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRegistrant,
				Value: ZFPDollar[2].str,
			}
		}
	case 97:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:677
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 98:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:681
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 99:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:686
		{
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			ZFPVAL.object = object.Object{
				Type:  object.OTInfraKey,
				Value: pkey,
			}
		}
	case 100:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:698
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 101:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:702
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 102:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:707
		{ //TODO CFE as of now there is only the rains key space. There will
			//be additional rules in case there are new key spaces
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			ZFPVAL.object = object.Object{
				Type:  object.OTExtraKey,
				Value: pkey,
			}
		}
	case 103:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:720
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 104:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:724
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 105:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:729
		{
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			pkey.ValidSince, pkey.ValidUntil, err = DecodeValidity(ZFPDollar[5].str, ZFPDollar[6].str)
			if err != nil {
				log.Error("semantic error:", "error", err)
			}
			ZFPVAL.object = object.Object{
				Type:  object.OTNextKey,
				Value: pkey,
			}
		}
	case 106:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:745
		{
			ZFPVAL.protocolType = object.PTUnspecified
		}
	case 107:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:749
		{
			ZFPVAL.protocolType = object.PTTLS
		}
	case 108:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:754
		{
			ZFPVAL.certUsage = object.CUTrustAnchor
		}
	case 109:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:758
		{
			ZFPVAL.certUsage = object.CUEndEntity
		}
	case 110:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:763
		{
			ZFPVAL.hashType = algorithmTypes.NoHashAlgo
		}
	case 111:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:767
		{
			ZFPVAL.hashType = algorithmTypes.Sha256
		}
	case 112:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:771
		{
			ZFPVAL.hashType = algorithmTypes.Sha384
		}
	case 113:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:775
		{
			ZFPVAL.hashType = algorithmTypes.Sha512
		}
	case 114:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:779
		{
			ZFPVAL.hashType = algorithmTypes.Fnv64
		}
	case 115:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:783
		{
			ZFPVAL.hashType = algorithmTypes.Murmur364
		}
	case 117:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:789
		{
			ZFPVAL.str = ZFPDollar[1].str + " " + ZFPDollar[2].str
		}
	case 118:
		ZFPDollar = ZFPS[ZFPpt-3 : ZFPpt+1]
		//line zonefileParser.y:794
		{
			ZFPVAL.signatures = ZFPDollar[2].signatures
		}
	case 119:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:799
		{
			ZFPVAL.signatures = []signature.Sig{ZFPDollar[1].signature}
		}
	case 120:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:803
		{
			ZFPVAL.signatures = append(ZFPDollar[1].signatures, ZFPDollar[2].signature)
		}
	case 122:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:809
		{
			data, err := DecodeEd25519SignatureData(ZFPDollar[2].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519SignatureData", err)
			}
			ZFPDollar[1].signature.Data = data
			ZFPVAL.signature = ZFPDollar[1].signature
		}
	case 123:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:819
		{
			publicKeyID, err := DecodePublicKeyID(ZFPDollar[4].str)
			if err != nil {
				log.Error("semantic error:", "DecodePublicKeyID", err)
			}
			validSince, validUntil, err := DecodeValidity(ZFPDollar[5].str, ZFPDollar[6].str)
			if err != nil {
				log.Error("semantic error:", "DecodeValidity", err)
			}
			ZFPVAL.signature = signature.Sig{
				PublicKeyID: publicKeyID,
				ValidSince:  validSince,
				ValidUntil:  validUntil,
			}
		}
	}
	goto ZFPstack /* stack new state and value */
}
