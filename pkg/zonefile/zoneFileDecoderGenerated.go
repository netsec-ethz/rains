// Code generated. DO NOT EDIT.

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

	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"strconv"
	"strings"
)

//AddSigs adds signatures to section
func AddSigs(sec section.WithSigForward, signatures []signature.Sig) {
	for _, sig := range signatures {
		sec.AddSig(sig)
	}
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

//line zonefileParser.y:119
type ZFPSymType struct {
	yys          int
	str          string
	assertion    *section.Assertion
	assertions   []*section.Assertion
	shard        *section.Shard
	pshard       *section.Pshard
	zone         *section.Zone
	sections     []section.WithSigForward
	objects      []object.Object
	object       object.Object
	objectTypes  []object.Type
	objectType   object.Type
	signatures   []signature.Sig
	signature    signature.Sig
	shardRange   []string
	publicKey    keys.PublicKey
	protocolType object.ProtocolType
	certUsage    object.CertificateUsage
	hashType     algorithmTypes.Hash
	bfAlgo       section.BloomFilterAlgo
}

const ID = 57346
const assertionType = 57347
const shardType = 57348
const pshardType = 57349
const zoneType = 57350
const nameType = 57351
const ip4Type = 57352
const ip6Type = 57353
const scionip4Type = 57354
const scionip6Type = 57355
const redirType = 57356
const delegType = 57357
const namesetType = 57358
const certType = 57359
const srvType = 57360
const regrType = 57361
const regtType = 57362
const infraType = 57363
const extraType = 57364
const nextType = 57365
const sigType = 57366
const ed25519Type = 57367
const unspecified = 57368
const tls = 57369
const trustAnchor = 57370
const endEntity = 57371
const noHash = 57372
const sha256 = 57373
const sha384 = 57374
const sha512 = 57375
const shake256 = 57376
const fnv64 = 57377
const fnv128 = 57378
const bloomKM12 = 57379
const bloomKM16 = 57380
const bloomKM20 = 57381
const bloomKM24 = 57382
const rains = 57383
const rangeBegin = 57384
const rangeEnd = 57385
const lBracket = 57386
const rBracket = 57387
const lParenthesis = 57388
const rParenthesis = 57389

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
	"scionip4Type",
	"scionip6Type",
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
	"shake256",
	"fnv64",
	"fnv128",
	"bloomKM12",
	"bloomKM16",
	"bloomKM20",
	"bloomKM24",
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

//line zonefileParser.y:701

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
	case TypeScionIP6:
		return scionip6Type
	case TypeScionIP4:
		return scionip4Type
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
	case TypeShake256:
		return shake256
	case TypeFnv64:
		return fnv64
	case TypeFnv128:
		return fnv128
	case TypeKM12:
		return bloomKM12
	case TypeKM16:
		return bloomKM16
	case TypeKM20:
		return bloomKM20
	case TypeKM24:
		return bloomKM24
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

const ZFPLast = 216

var ZFPAct = [...]int{

	129, 3, 37, 38, 85, 11, 130, 131, 132, 133,
	134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
	144, 54, 56, 55, 57, 58, 59, 60, 61, 62,
	63, 64, 65, 66, 67, 68, 16, 27, 109, 97,
	96, 77, 163, 74, 75, 159, 11, 29, 95, 100,
	98, 103, 104, 105, 106, 71, 27, 158, 113, 114,
	33, 147, 148, 149, 150, 151, 152, 153, 70, 91,
	92, 54, 56, 55, 57, 58, 59, 60, 61, 62,
	63, 64, 65, 66, 67, 68, 125, 28, 101, 99,
	122, 123, 124, 72, 88, 89, 94, 93, 84, 119,
	73, 36, 25, 15, 167, 166, 165, 76, 162, 126,
	161, 157, 17, 18, 19, 11, 12, 13, 14, 156,
	155, 154, 160, 77, 145, 1, 127, 34, 118, 164,
	130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
	140, 141, 142, 143, 144, 54, 56, 55, 57, 58,
	59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
	117, 116, 111, 115, 110, 108, 86, 90, 83, 82,
	81, 80, 79, 78, 69, 35, 32, 31, 30, 23,
	22, 21, 20, 102, 121, 146, 112, 87, 26, 24,
	128, 53, 52, 51, 50, 49, 48, 47, 46, 45,
	44, 43, 42, 40, 41, 39, 7, 107, 120, 9,
	5, 8, 4, 2, 10, 6,
}
var ZFPPact = [...]int{

	-1000, -1000, 110, -1000, -1000, -1000, -1000, -10, -10, -10,
	-10, 178, 177, 176, 175, -1000, 32, -1000, -1000, -1000,
	43, 174, 173, 172, 13, -1000, 171, 76, 136, 170,
	51, 51, -1, -1000, -1000, -1000, 3, 62, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, 169, 168, 167, 166, 165, 164,
	73, 162, 68, 163, 162, 162, 72, 71, 23, -4,
	-5, 46, 45, 14, -1000, 161, -1000, -1000, -6, -1000,
	-1000, -1000, -1000, -1000, 160, 158, -1000, 30, -1000, -1000,
	159, 158, 158, 157, 156, 124, 136, -1000, -1000, -1000,
	-1000, -1000, 56, -1000, -1000, -1000, -1000, 41, 122, 121,
	120, -1000, 31, -1000, -1000, 117, 116, 115, 107, 12,
	0, 106, -1000, -1000, -1000, -1000, -1000, 104, -3, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, 102, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, 101, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, 100, -1000,
}
var ZFPPgo = [...]int{

	0, 215, 214, 213, 212, 211, 68, 210, 209, 208,
	207, 1, 206, 2, 3, 205, 204, 203, 202, 201,
	200, 199, 198, 197, 196, 195, 194, 193, 192, 191,
	190, 0, 103, 189, 102, 188, 4, 187, 186, 185,
	184, 183, 125,
}
var ZFPR1 = [...]int{

	0, 42, 3, 3, 3, 3, 3, 1, 1, 2,
	10, 10, 4, 4, 5, 6, 6, 6, 6, 9,
	9, 7, 7, 8, 40, 40, 40, 41, 41, 41,
	41, 11, 11, 12, 12, 13, 13, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 15, 30, 30, 31, 31, 31, 31, 31,
	31, 31, 31, 31, 31, 31, 31, 31, 31, 31,
	17, 16, 19, 18, 20, 21, 22, 23, 24, 25,
	26, 27, 28, 29, 37, 37, 38, 38, 39, 39,
	39, 39, 39, 39, 39, 36, 36, 32, 33, 33,
	34, 34, 35,
}
var ZFPR2 = [...]int{

	0, 1, 0, 2, 2, 2, 2, 1, 2, 6,
	0, 2, 1, 2, 7, 2, 2, 2, 2, 0,
	2, 1, 2, 7, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 5, 7, 1, 2, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 5, 1, 2, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 4, 2, 5, 4, 2,
	2, 4, 4, 6, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 2, 3, 1, 2,
	1, 2, 6,
}
var ZFPChk = [...]int{

	-1000, -42, -3, -11, -4, -7, -1, -12, -5, -8,
	-2, 5, 6, 7, 8, -32, 46, -32, -32, -32,
	4, 4, 4, 4, -33, -34, -35, 24, 44, 4,
	4, 4, 4, 47, -34, 4, 25, -13, -14, -15,
	-17, -16, -18, -19, -20, -21, -22, -23, -24, -25,
	-26, -27, -28, -29, 9, 11, 10, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 4,
	-6, 4, 42, -6, 44, 41, 45, -14, 4, 4,
	4, 4, 4, 4, 25, -36, 4, -37, 26, 27,
	4, -36, -36, 25, 25, 25, 44, 44, 4, 43,
	4, 43, -41, 37, 38, 39, 40, -10, 4, 44,
	4, 4, -38, 28, 29, 4, 4, 4, 4, -13,
	-9, -40, 34, 35, 36, 45, -11, 4, -30, -31,
	9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
	19, 20, 21, 22, 23, 4, -39, 30, 31, 32,
	33, 34, 35, 36, 4, 4, 4, 4, 45, 45,
	-11, 4, 4, 45, -31, 4, 4, 4,
}
var ZFPDef = [...]int{

	2, -2, 1, 3, 4, 5, 6, 31, 12, 21,
	7, 0, 0, 0, 0, 32, 0, 13, 22, 8,
	0, 0, 0, 0, 0, 98, 100, 0, 0, 0,
	0, 0, 0, 97, 99, 101, 0, 0, 35, 37,
	38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
	48, 49, 50, 51, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 10, 0, 33, 36, 0, 70,
	71, 73, 72, 74, 0, 76, 95, 0, 84, 85,
	0, 79, 80, 0, 0, 0, 0, 19, 15, 17,
	16, 18, 0, 27, 28, 29, 30, 0, 0, 0,
	0, 96, 0, 86, 87, 0, 0, 0, 0, 0,
	0, 0, 24, 25, 26, 9, 11, 0, 0, 53,
	55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	65, 66, 67, 68, 69, 75, 0, 88, 89, 90,
	91, 92, 93, 94, 78, 81, 82, 0, 34, 14,
	20, 23, 102, 52, 54, 77, 0, 83,
}
var ZFPTok1 = [...]int{

	1,
}
var ZFPTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 47,
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
//line zonefileParser.y:190
		{
			output = ZFPDollar[1].sections
		}
	case 2:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
//line zonefileParser.y:195
		{
			ZFPVAL.sections = nil
		}
	case 3:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:199
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].assertion)
		}
	case 4:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:203
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].shard)
		}
	case 5:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:207
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].pshard)
		}
	case 6:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:211
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].zone)
		}
	case 8:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:217
		{
			AddSigs(ZFPDollar[1].zone, ZFPDollar[2].signatures)
			ZFPVAL.zone = ZFPDollar[1].zone
		}
	case 9:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
//line zonefileParser.y:223
		{
			ZFPVAL.zone = &section.Zone{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				Content:     ZFPDollar[5].assertions,
			}
		}
	case 10:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
//line zonefileParser.y:232
		{
			ZFPVAL.assertions = nil
		}
	case 11:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:236
		{
			ZFPVAL.assertions = append(ZFPDollar[1].assertions, ZFPDollar[2].assertion)
		}
	case 13:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:242
		{
			AddSigs(ZFPDollar[1].shard, ZFPDollar[2].signatures)
			ZFPVAL.shard = ZFPDollar[1].shard
		}
	case 14:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
//line zonefileParser.y:248
		{
			ZFPVAL.shard = &section.Shard{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				RangeFrom:   ZFPDollar[4].shardRange[0],
				RangeTo:     ZFPDollar[4].shardRange[1],
				Content:     ZFPDollar[6].assertions,
			}
		}
	case 15:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:259
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ZFPDollar[2].str}
		}
	case 16:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:263
		{
			ZFPVAL.shardRange = []string{"<", ZFPDollar[2].str}
		}
	case 17:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:267
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ">"}
		}
	case 18:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:271
		{
			ZFPVAL.shardRange = []string{"<", ">"}
		}
	case 19:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
//line zonefileParser.y:276
		{
			ZFPVAL.assertions = nil
		}
	case 20:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:280
		{
			ZFPVAL.assertions = append(ZFPDollar[1].assertions, ZFPDollar[2].assertion)
		}
	case 22:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:286
		{
			AddSigs(ZFPDollar[1].pshard, ZFPDollar[2].signatures)
			ZFPVAL.pshard = ZFPDollar[1].pshard
		}
	case 23:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
//line zonefileParser.y:292
		{
			decodedFilter, err := hex.DecodeString(ZFPDollar[7].str)
			if err != nil {
				log.Error("semantic error:", "Was not able to decode Bloom filter", err)
			}
			ZFPVAL.pshard = &section.Pshard{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				RangeFrom:   ZFPDollar[4].shardRange[0],
				RangeTo:     ZFPDollar[4].shardRange[1],
				BloomFilter: section.BloomFilter{
					Algorithm: ZFPDollar[5].bfAlgo,
					Hash:      ZFPDollar[6].hashType,
					Filter:    bitarray.BitArray(decodedFilter),
				},
			}
		}
	case 24:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:311
		{
			ZFPVAL.hashType = algorithmTypes.Shake256
		}
	case 25:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:315
		{
			ZFPVAL.hashType = algorithmTypes.Fnv64
		}
	case 26:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:319
		{
			ZFPVAL.hashType = algorithmTypes.Fnv128
		}
	case 27:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:324
		{
			ZFPVAL.bfAlgo = section.BloomKM12
		}
	case 28:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:328
		{
			ZFPVAL.bfAlgo = section.BloomKM16
		}
	case 29:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:332
		{
			ZFPVAL.bfAlgo = section.BloomKM20
		}
	case 30:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:336
		{
			ZFPVAL.bfAlgo = section.BloomKM24
		}
	case 32:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:342
		{
			AddSigs(ZFPDollar[1].assertion, ZFPDollar[2].signatures)
			ZFPVAL.assertion = ZFPDollar[1].assertion
		}
	case 33:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
//line zonefileParser.y:348
		{
			ZFPVAL.assertion = &section.Assertion{
				SubjectName: ZFPDollar[2].str,
				Content:     ZFPDollar[4].objects,
			}
		}
	case 34:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
//line zonefileParser.y:355
		{
			ZFPVAL.assertion = &section.Assertion{
				SubjectName: ZFPDollar[2].str,
				SubjectZone: ZFPDollar[3].str,
				Context:     ZFPDollar[4].str,
				Content:     ZFPDollar[6].objects,
			}
		}
	case 35:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:365
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 36:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:369
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 52:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
//line zonefileParser.y:390
		{
			ZFPVAL.object = object.Object{
				Type: object.OTName,
				Value: object.Name{
					Name:  ZFPDollar[2].str,
					Types: ZFPDollar[4].objectTypes,
				},
			}
		}
	case 53:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:401
		{
			ZFPVAL.objectTypes = []object.Type{ZFPDollar[1].objectType}
		}
	case 54:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:405
		{
			ZFPVAL.objectTypes = append(ZFPDollar[1].objectTypes, ZFPDollar[2].objectType)
		}
	case 55:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:410
		{
			ZFPVAL.objectType = object.OTName
		}
	case 56:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:414
		{
			ZFPVAL.objectType = object.OTIP4Addr
		}
	case 57:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:418
		{
			ZFPVAL.objectType = object.OTIP6Addr
		}
	case 58:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:422
		{
			ZFPVAL.objectType = object.OTScionAddr4
		}
	case 59:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:426
		{
			ZFPVAL.objectType = object.OTScionAddr6
		}
	case 60:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:430
		{
			ZFPVAL.objectType = object.OTRedirection
		}
	case 61:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:434
		{
			ZFPVAL.objectType = object.OTDelegation
		}
	case 62:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:438
		{
			ZFPVAL.objectType = object.OTNameset
		}
	case 63:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:442
		{
			ZFPVAL.objectType = object.OTCertInfo
		}
	case 64:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:446
		{
			ZFPVAL.objectType = object.OTServiceInfo
		}
	case 65:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:450
		{
			ZFPVAL.objectType = object.OTRegistrar
		}
	case 66:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:454
		{
			ZFPVAL.objectType = object.OTRegistrant
		}
	case 67:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:458
		{
			ZFPVAL.objectType = object.OTInfraKey
		}
	case 68:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:462
		{
			ZFPVAL.objectType = object.OTExtraKey
		}
	case 69:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:466
		{
			ZFPVAL.objectType = object.OTNextKey
		}
	case 70:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:470
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTIP6Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 71:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:477
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTIP4Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 72:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:484
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTScionAddr6,
				Value: ZFPDollar[2].str,
			}
		}
	case 73:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:491
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTScionAddr4,
				Value: ZFPDollar[2].str,
			}
		}
	case 74:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:498
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRedirection,
				Value: ZFPDollar[2].str,
			}
		}
	case 75:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
//line zonefileParser.y:506
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
	case 76:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:518
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTNameset,
				Value: ZFPDollar[2].str,
			}
		}
	case 77:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
//line zonefileParser.y:526
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
	case 78:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
//line zonefileParser.y:538
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
	case 79:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:550
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRegistrar,
				Value: ZFPDollar[2].str,
			}
		}
	case 80:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:558
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRegistrant,
				Value: ZFPDollar[2].str,
			}
		}
	case 81:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
//line zonefileParser.y:566
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
	case 82:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
//line zonefileParser.y:578
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
	case 83:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
//line zonefileParser.y:591
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
	case 84:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:607
		{
			ZFPVAL.protocolType = object.PTUnspecified
		}
	case 85:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:611
		{
			ZFPVAL.protocolType = object.PTTLS
		}
	case 86:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:616
		{
			ZFPVAL.certUsage = object.CUTrustAnchor
		}
	case 87:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:620
		{
			ZFPVAL.certUsage = object.CUEndEntity
		}
	case 88:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:625
		{
			ZFPVAL.hashType = algorithmTypes.NoHashAlgo
		}
	case 89:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:629
		{
			ZFPVAL.hashType = algorithmTypes.Sha256
		}
	case 90:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:633
		{
			ZFPVAL.hashType = algorithmTypes.Sha384
		}
	case 91:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:637
		{
			ZFPVAL.hashType = algorithmTypes.Sha512
		}
	case 92:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:641
		{
			ZFPVAL.hashType = algorithmTypes.Shake256
		}
	case 93:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:645
		{
			ZFPVAL.hashType = algorithmTypes.Fnv64
		}
	case 94:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:649
		{
			ZFPVAL.hashType = algorithmTypes.Fnv128
		}
	case 96:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:655
		{
			ZFPVAL.str = ZFPDollar[1].str + " " + ZFPDollar[2].str
		}
	case 97:
		ZFPDollar = ZFPS[ZFPpt-3 : ZFPpt+1]
//line zonefileParser.y:660
		{
			ZFPVAL.signatures = ZFPDollar[2].signatures
		}
	case 98:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
//line zonefileParser.y:665
		{
			ZFPVAL.signatures = []signature.Sig{ZFPDollar[1].signature}
		}
	case 99:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:669
		{
			ZFPVAL.signatures = append(ZFPDollar[1].signatures, ZFPDollar[2].signature)
		}
	case 101:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
//line zonefileParser.y:675
		{
			sigData, err := hex.DecodeString(ZFPDollar[2].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519SignatureData", err)
			}
			ZFPDollar[1].signature.Data = sigData
			ZFPVAL.signature = ZFPDollar[1].signature
		}
	case 102:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
//line zonefileParser.y:685
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
