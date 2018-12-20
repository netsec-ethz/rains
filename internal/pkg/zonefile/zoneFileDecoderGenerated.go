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
	"io/ioutil"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"golang.org/x/crypto/ed25519"
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
const shake256 = 57374
const fnv64 = 57375
const fnv128 = 57376
const bloomKM12 = 57377
const bloomKM16 = 57378
const bloomKM20 = 57379
const bloomKM24 = 57380
const rains = 57381
const rangeBegin = 57382
const rangeEnd = 57383
const lBracket = 57384
const rBracket = 57385
const lParenthesis = 57386
const rParenthesis = 57387

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

//line zonefileParser.y:789

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

const ZFPLast = 212

var ZFPAct = [...]int{

	147, 3, 37, 103, 148, 149, 150, 151, 152, 153,
	154, 155, 156, 157, 158, 159, 160, 63, 61, 62,
	27, 57, 60, 11, 59, 11, 58, 16, 174, 56,
	84, 127, 55, 115, 114, 82, 29, 25, 179, 54,
	52, 118, 116, 33, 121, 122, 123, 124, 79, 53,
	163, 164, 165, 166, 167, 168, 169, 51, 83, 78,
	76, 175, 34, 143, 106, 107, 91, 95, 97, 96,
	94, 93, 92, 90, 28, 89, 109, 110, 119, 117,
	86, 88, 131, 132, 80, 140, 141, 142, 113, 112,
	87, 81, 111, 102, 36, 27, 85, 148, 149, 150,
	151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
	75, 74, 73, 72, 71, 70, 69, 137, 68, 15,
	67, 65, 11, 12, 13, 14, 66, 144, 17, 18,
	19, 64, 183, 182, 181, 178, 177, 173, 172, 171,
	176, 170, 161, 1, 145, 136, 135, 180, 64, 66,
	65, 67, 68, 69, 70, 71, 72, 73, 74, 75,
	76, 134, 129, 133, 128, 126, 104, 108, 101, 100,
	99, 98, 77, 35, 32, 31, 30, 23, 22, 21,
	20, 120, 139, 162, 130, 105, 26, 24, 146, 50,
	49, 48, 47, 46, 45, 44, 43, 42, 41, 39,
	40, 38, 7, 125, 138, 9, 5, 8, 4, 2,
	10, 6,
}
var ZFPPact = [...]int{

	-1000, -1000, 117, -1000, -1000, -1000, -1000, -17, -17, -17,
	-17, 176, 175, 174, 173, -1000, 73, -1000, -1000, -1000,
	32, 172, 171, 170, -2, -1000, 169, 71, 139, 168,
	44, 44, -7, -1000, -1000, -1000, 19, -13, 122, 110,
	116, 108, 105, 102, 100, 98, 96, 94, 92, 90,
	39, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, 167, 166, 165, 164, 70, 162,
	40, 163, 162, 162, 69, 66, 65, -8, -9, 38,
	37, 9, -1000, 161, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -11, -1000,
	-1000, -1000, 160, 158, -1000, 56, -1000, -1000, 159, 158,
	158, 157, 142, 141, 139, -1000, -1000, -1000, -1000, -1000,
	53, -1000, -1000, -1000, -1000, 20, 140, 88, 138, -1000,
	22, -1000, -1000, 137, 135, 134, 133, -15, 18, 132,
	-1000, -1000, -1000, -1000, -1000, 131, -5, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, 130, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, 129, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, 128, -1000,
}
var ZFPPgo = [...]int{

	0, 211, 210, 209, 208, 207, 59, 206, 205, 204,
	203, 1, 202, 2, 201, 200, 199, 198, 197, 196,
	195, 194, 193, 192, 191, 190, 189, 57, 49, 40,
	39, 32, 29, 21, 26, 24, 22, 18, 19, 17,
	188, 0, 119, 187, 37, 186, 3, 185, 184, 183,
	182, 181, 143,
}
var ZFPR1 = [...]int{

	0, 52, 3, 3, 3, 3, 3, 1, 1, 2,
	10, 10, 4, 4, 5, 6, 6, 6, 6, 9,
	9, 7, 7, 8, 50, 50, 50, 51, 51, 51,
	51, 11, 11, 12, 12, 13, 13, 13, 13, 13,
	13, 13, 13, 13, 13, 13, 13, 13, 14, 14,
	27, 40, 40, 41, 41, 41, 41, 41, 41, 41,
	41, 41, 41, 41, 41, 41, 16, 16, 29, 15,
	15, 28, 17, 17, 30, 18, 18, 31, 19, 19,
	32, 20, 20, 33, 21, 21, 34, 22, 22, 35,
	23, 23, 36, 24, 24, 37, 25, 25, 38, 26,
	26, 39, 47, 47, 48, 48, 49, 49, 49, 49,
	49, 49, 49, 46, 46, 42, 43, 43, 44, 44,
	45,
}
var ZFPR2 = [...]int{

	0, 1, 0, 2, 2, 2, 2, 1, 2, 6,
	0, 2, 1, 2, 7, 2, 2, 2, 2, 0,
	2, 1, 2, 7, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 5, 7, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 2,
	5, 1, 2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 2, 2, 1,
	2, 2, 1, 2, 2, 1, 2, 4, 1, 2,
	2, 1, 2, 5, 1, 2, 4, 1, 2, 2,
	1, 2, 2, 1, 2, 4, 1, 2, 4, 1,
	2, 6, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 2, 3, 1, 2, 1, 2,
	6,
}
var ZFPChk = [...]int{

	-1000, -52, -3, -11, -4, -7, -1, -12, -5, -8,
	-2, 5, 6, 7, 8, -42, 44, -42, -42, -42,
	4, 4, 4, 4, -43, -44, -45, 22, 42, 4,
	4, 4, 4, 45, -44, 4, 23, -13, -14, -16,
	-15, -17, -18, -19, -20, -21, -22, -23, -24, -25,
	-26, -27, -29, -28, -30, -31, -32, -33, -34, -35,
	-36, -37, -38, -39, 9, 11, 10, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 4, -6, 4,
	40, -6, 42, 39, 43, -27, -29, -28, -30, -31,
	-32, -33, -34, -35, -36, -37, -38, -39, 4, 4,
	4, 4, 23, -46, 4, -47, 24, 25, 4, -46,
	-46, 23, 23, 23, 42, 42, 4, 41, 4, 41,
	-51, 35, 36, 37, 38, -10, 4, 42, 4, 4,
	-48, 26, 27, 4, 4, 4, 4, -13, -9, -50,
	32, 33, 34, 43, -11, 4, -40, -41, 9, 10,
	11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 4, -49, 28, 29, 30, 31, 32, 33, 34,
	4, 4, 4, 4, 43, 43, -11, 4, 4, 43,
	-41, 4, 4, 4,
}
var ZFPDef = [...]int{

	2, -2, 1, 3, 4, 5, 6, 31, 12, 21,
	7, 0, 0, 0, 0, 32, 0, 13, 22, 8,
	0, 0, 0, 0, 0, 116, 118, 0, 0, 0,
	0, 0, 0, 115, 117, 119, 0, 0, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
	47, 48, 66, 69, 72, 75, 78, 81, 84, 87,
	90, 93, 96, 99, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 10, 0, 33, 49, 67, 70, 73, 76,
	79, 82, 85, 88, 91, 94, 97, 100, 0, 68,
	71, 74, 0, 80, 113, 0, 102, 103, 0, 89,
	92, 0, 0, 0, 0, 19, 15, 17, 16, 18,
	0, 27, 28, 29, 30, 0, 0, 0, 0, 114,
	0, 104, 105, 0, 0, 0, 0, 0, 0, 0,
	24, 25, 26, 9, 11, 0, 0, 51, 53, 54,
	55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	65, 77, 0, 106, 107, 108, 109, 110, 111, 112,
	86, 95, 98, 0, 34, 14, 20, 23, 120, 50,
	52, 83, 0, 101,
}
var ZFPTok1 = [...]int{

	1,
}
var ZFPTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45,
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
		//line zonefileParser.y:191
		{
			output = ZFPDollar[1].sections
		}
	case 2:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:196
		{
			ZFPVAL.sections = nil
		}
	case 3:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:200
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].assertion)
		}
	case 4:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:204
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].shard)
		}
	case 5:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:208
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].pshard)
		}
	case 6:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:212
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].zone)
		}
	case 8:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:218
		{
			AddSigs(ZFPDollar[1].zone, ZFPDollar[2].signatures)
			ZFPVAL.zone = ZFPDollar[1].zone
		}
	case 9:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:224
		{
			ZFPVAL.zone = &section.Zone{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				Content:     ZFPDollar[5].assertions,
			}
		}
	case 10:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:233
		{
			ZFPVAL.assertions = nil
		}
	case 11:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:237
		{
			ZFPVAL.assertions = append(ZFPDollar[1].assertions, ZFPDollar[2].assertion)
		}
	case 13:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:243
		{
			AddSigs(ZFPDollar[1].shard, ZFPDollar[2].signatures)
			ZFPVAL.shard = ZFPDollar[1].shard
		}
	case 14:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:249
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
		//line zonefileParser.y:260
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ZFPDollar[2].str}
		}
	case 16:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:264
		{
			ZFPVAL.shardRange = []string{"<", ZFPDollar[2].str}
		}
	case 17:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:268
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ">"}
		}
	case 18:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:272
		{
			ZFPVAL.shardRange = []string{"<", ">"}
		}
	case 19:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:277
		{
			ZFPVAL.assertions = nil
		}
	case 20:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:281
		{
			ZFPVAL.assertions = append(ZFPDollar[1].assertions, ZFPDollar[2].assertion)
		}
	case 22:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:287
		{
			AddSigs(ZFPDollar[1].pshard, ZFPDollar[2].signatures)
			ZFPVAL.pshard = ZFPDollar[1].pshard
		}
	case 23:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:293
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
		//line zonefileParser.y:312
		{
			ZFPVAL.hashType = algorithmTypes.Shake256
		}
	case 25:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:316
		{
			ZFPVAL.hashType = algorithmTypes.Fnv64
		}
	case 26:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:320
		{
			ZFPVAL.hashType = algorithmTypes.Fnv128
		}
	case 27:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:325
		{
			ZFPVAL.bfAlgo = section.BloomKM12
		}
	case 28:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:329
		{
			ZFPVAL.bfAlgo = section.BloomKM16
		}
	case 29:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:333
		{
			ZFPVAL.bfAlgo = section.BloomKM20
		}
	case 30:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:337
		{
			ZFPVAL.bfAlgo = section.BloomKM24
		}
	case 32:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:343
		{
			AddSigs(ZFPDollar[1].assertion, ZFPDollar[2].signatures)
			ZFPVAL.assertion = ZFPDollar[1].assertion
		}
	case 33:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:349
		{
			ZFPVAL.assertion = &section.Assertion{
				SubjectName: ZFPDollar[2].str,
				Content:     ZFPDollar[4].objects,
			}
		}
	case 34:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:356
		{
			ZFPVAL.assertion = &section.Assertion{
				SubjectName: ZFPDollar[2].str,
				SubjectZone: ZFPDollar[3].str,
				Context:     ZFPDollar[4].str,
				Content:     ZFPDollar[6].objects,
			}
		}
	case 48:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:380
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 49:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:384
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 50:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:389
		{
			ZFPVAL.object = object.Object{
				Type: object.OTName,
				Value: object.Name{
					Name:  ZFPDollar[2].str,
					Types: ZFPDollar[4].objectTypes,
				},
			}
		}
	case 51:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:400
		{
			ZFPVAL.objectTypes = []object.Type{ZFPDollar[1].objectType}
		}
	case 52:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:404
		{
			ZFPVAL.objectTypes = append(ZFPDollar[1].objectTypes, ZFPDollar[2].objectType)
		}
	case 53:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:409
		{
			ZFPVAL.objectType = object.OTName
		}
	case 54:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:413
		{
			ZFPVAL.objectType = object.OTIP4Addr
		}
	case 55:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:417
		{
			ZFPVAL.objectType = object.OTIP6Addr
		}
	case 56:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:421
		{
			ZFPVAL.objectType = object.OTRedirection
		}
	case 57:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:425
		{
			ZFPVAL.objectType = object.OTDelegation
		}
	case 58:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:429
		{
			ZFPVAL.objectType = object.OTNameset
		}
	case 59:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:433
		{
			ZFPVAL.objectType = object.OTCertInfo
		}
	case 60:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:437
		{
			ZFPVAL.objectType = object.OTServiceInfo
		}
	case 61:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:441
		{
			ZFPVAL.objectType = object.OTRegistrar
		}
	case 62:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:445
		{
			ZFPVAL.objectType = object.OTRegistrant
		}
	case 63:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:449
		{
			ZFPVAL.objectType = object.OTInfraKey
		}
	case 64:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:453
		{
			ZFPVAL.objectType = object.OTExtraKey
		}
	case 65:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:457
		{
			ZFPVAL.objectType = object.OTNextKey
		}
	case 66:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:462
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 67:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:466
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 68:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:471
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTIP6Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 69:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:479
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 70:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:483
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 71:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:488
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTIP4Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 72:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:496
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 73:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:500
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 74:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:505
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRedirection,
				Value: ZFPDollar[2].str,
			}
		}
	case 75:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:513
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 76:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:517
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 77:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:522
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
	case 78:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:534
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 79:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:538
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 80:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:543
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTNameset,
				Value: ZFPDollar[2].str,
			}
		}
	case 81:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:551
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 82:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:555
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 83:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:560
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
	case 84:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:572
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 85:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:576
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 86:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:581
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
	case 87:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:593
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 88:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:597
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 89:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:602
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRegistrar,
				Value: ZFPDollar[2].str,
			}
		}
	case 90:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:610
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 91:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:614
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 92:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:619
		{
			ZFPVAL.object = object.Object{
				Type:  object.OTRegistrant,
				Value: ZFPDollar[2].str,
			}
		}
	case 93:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:627
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 94:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:631
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 95:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:636
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
	case 96:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:648
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 97:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:652
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 98:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:657
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
	case 99:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:670
		{
			ZFPVAL.objects = []object.Object{ZFPDollar[1].object}
		}
	case 100:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:674
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 101:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:679
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
	case 102:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:695
		{
			ZFPVAL.protocolType = object.PTUnspecified
		}
	case 103:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:699
		{
			ZFPVAL.protocolType = object.PTTLS
		}
	case 104:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:704
		{
			ZFPVAL.certUsage = object.CUTrustAnchor
		}
	case 105:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:708
		{
			ZFPVAL.certUsage = object.CUEndEntity
		}
	case 106:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:713
		{
			ZFPVAL.hashType = algorithmTypes.NoHashAlgo
		}
	case 107:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:717
		{
			ZFPVAL.hashType = algorithmTypes.Sha256
		}
	case 108:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:721
		{
			ZFPVAL.hashType = algorithmTypes.Sha384
		}
	case 109:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:725
		{
			ZFPVAL.hashType = algorithmTypes.Sha512
		}
	case 110:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:729
		{
			ZFPVAL.hashType = algorithmTypes.Shake256
		}
	case 111:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:733
		{
			ZFPVAL.hashType = algorithmTypes.Fnv64
		}
	case 112:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:737
		{
			ZFPVAL.hashType = algorithmTypes.Fnv128
		}
	case 114:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:743
		{
			ZFPVAL.str = ZFPDollar[1].str + " " + ZFPDollar[2].str
		}
	case 115:
		ZFPDollar = ZFPS[ZFPpt-3 : ZFPpt+1]
		//line zonefileParser.y:748
		{
			ZFPVAL.signatures = ZFPDollar[2].signatures
		}
	case 116:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:753
		{
			ZFPVAL.signatures = []signature.Sig{ZFPDollar[1].signature}
		}
	case 117:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:757
		{
			ZFPVAL.signatures = append(ZFPDollar[1].signatures, ZFPDollar[2].signature)
		}
	case 119:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:763
		{
			sigData, err := hex.DecodeString(ZFPDollar[2].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519SignatureData", err)
			}
			ZFPDollar[1].signature.Data = sigData
			ZFPVAL.signature = ZFPDollar[1].signature
		}
	case 120:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:773
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
