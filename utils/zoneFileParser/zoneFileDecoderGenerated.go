/*
 * Modification made to generated file marked with 'start CFE' and 'end CFE'
 * changed package name
 */

//line zonefileParser.y:8
package zoneFileParser

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
	"github.com/netsec-ethz/rains/rainslib"
	"golang.org/x/crypto/ed25519"
)

//AddSigs adds signatures to section
func AddSigs(section rainslib.MessageSectionWithSigForward, signatures []rainslib.Signature) {
	for _, sig := range signatures {
		section.AddSig(sig)
	}
}

func DecodePublicKeyID(keyphase string) (rainslib.PublicKeyID, error) {
	phase, err := strconv.Atoi(keyphase)
	if err != nil {
		return rainslib.PublicKeyID{}, errors.New("keyphase is not a number")
	}
	return rainslib.PublicKeyID{
		Algorithm: rainslib.Ed25519,
		KeyPhase:  phase,
		KeySpace:  rainslib.RainsKeySpace,
	}, nil
}

func DecodeEd25519SignatureData(input string) (interface{}, error) {
	return "notYetImplemented", nil
}

// DecodeEd25519PublicKeyData returns the publicKey or an error in case
// pkeyInput is malformed i.e. it is not in zone file format.
func DecodeEd25519PublicKeyData(pkeyInput string, keyphase string) (rainslib.PublicKey, error) {
	publicKeyID, err := DecodePublicKeyID(keyphase)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	pKey, err := hex.DecodeString(pkeyInput)
	if err != nil {
		return rainslib.PublicKey{}, err
	}
	if len(pKey) == 32 {
		publicKey := rainslib.PublicKey{Key: ed25519.PublicKey(pKey), PublicKeyID: publicKeyID}
		return publicKey, nil
	}
	return rainslib.PublicKey{}, fmt.Errorf("wrong public key length: got %d, want: 32", len(pKey))
}

func DecodeCertificate(ptype rainslib.ProtocolType, usage rainslib.CertificateUsage,
	hashAlgo rainslib.HashAlgorithmType, certificat string) (rainslib.CertificateObject,
	error) {
	data, err := hex.DecodeString(certificat)
	if err != nil {
		return rainslib.CertificateObject{}, err
	}
	return rainslib.CertificateObject{
		Type:     ptype,
		Usage:    usage,
		HashAlgo: hashAlgo,
		Data:     data,
	}, nil
}

func DecodeSrv(name, portString, priorityString string) (rainslib.ServiceInfo, error) {
	port, err := strconv.Atoi(portString)
	if err != nil || port < 0 || port > 65535 {
		return rainslib.ServiceInfo{}, errors.New("Port is not a number or out of range")
	}
	priority, err := strconv.Atoi(priorityString)
	if err != nil || port < 0 {
		return rainslib.ServiceInfo{}, errors.New("Priority is not a number or negative")
	}
	return rainslib.ServiceInfo{
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
var output []rainslib.MessageSectionWithSigForward

//line zonefileParser.y:117
type ZFPSymType struct {
	yys          int
	str          string
	assertion    *rainslib.AssertionSection
	assertions   []*rainslib.AssertionSection
	shard        *rainslib.ShardSection
	zone         *rainslib.ZoneSection
	sections     []rainslib.MessageSectionWithSigForward
	objects      []rainslib.Object
	object       rainslib.Object
	objectTypes  []rainslib.ObjectType
	objectType   rainslib.ObjectType
	signatures   []rainslib.Signature
	signature    rainslib.Signature
	shardRange   []string
	publicKey    rainslib.PublicKey
	protocolType rainslib.ProtocolType
	certUsage    rainslib.CertificateUsage
	hashType     rainslib.HashAlgorithmType
}

const ID = 57346
const assertionType = 57347
const shardType = 57348
const zoneType = 57349
const nameType = 57350
const ip4Type = 57351
const ip6Type = 57352
const redirType = 57353
const delegType = 57354
const namesetType = 57355
const certType = 57356
const srvType = 57357
const regrType = 57358
const regtType = 57359
const infraType = 57360
const extraType = 57361
const nextType = 57362
const sigType = 57363
const ed25519Type = 57364
const unspecified = 57365
const tls = 57366
const trustAnchor = 57367
const endEntity = 57368
const noHash = 57369
const sha256 = 57370
const sha384 = 57371
const sha512 = 57372
const rains = 57373
const rangeBegin = 57374
const rangeEnd = 57375
const lBracket = 57376
const rBracket = 57377
const lParenthesis = 57378
const rParenthesis = 57379

var ZFPToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"ID",
	"assertionType",
	"shardType",
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

//line zonefileParser.y:721

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
	case ":A:":
		return assertionType
	case ":S:":
		return shardType
	case ":Z:":
		return zoneType
	case ":name:":
		return nameType
	case ":ip6:":
		return ip6Type
	case ":ip4:":
		return ip4Type
	case ":redir:":
		return redirType
	case ":deleg:":
		return delegType
	case ":nameset:":
		return namesetType
	case ":cert:":
		return certType
	case ":srv:":
		return srvType
	case ":regr:":
		return regrType
	case ":regt:":
		return regtType
	case ":infra:":
		return infraType
	case ":extra:":
		return extraType
	case ":next:":
		return nextType
	case ":sig:":
		return sigType
	case ":ed25519:":
		return ed25519Type
	case ":unspecified:":
		return unspecified
	case ":tls:":
		return tls
	case ":trustAnchor:":
		return trustAnchor
	case ":endEntity:":
		return endEntity
	case ":noHash:":
		return noHash
	case ":sha256:":
		return sha256
	case ":sha384:":
		return sha384
	case ":sha512:":
		return sha512
	case ":rains:":
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

const ZFPLast = 201

var ZFPAct = [...]int{

	137, 117, 4, 80, 3, 37, 102, 63, 61, 62,
	138, 139, 140, 141, 142, 143, 144, 145, 146, 147,
	148, 149, 150, 60, 58, 59, 55, 53, 57, 24,
	56, 9, 10, 54, 9, 9, 52, 164, 51, 13,
	161, 83, 82, 120, 114, 33, 113, 81, 26, 29,
	124, 125, 115, 30, 27, 105, 106, 94, 96, 95,
	79, 132, 17, 112, 162, 116, 76, 111, 86, 88,
	91, 93, 92, 90, 89, 87, 85, 84, 25, 108,
	109, 28, 31, 28, 153, 154, 155, 156, 19, 18,
	19, 138, 139, 140, 141, 142, 143, 144, 145, 146,
	147, 148, 149, 150, 64, 66, 65, 67, 68, 69,
	70, 71, 72, 73, 74, 75, 76, 78, 131, 130,
	133, 134, 110, 101, 36, 22, 24, 75, 74, 73,
	72, 71, 70, 69, 68, 67, 65, 165, 66, 64,
	12, 9, 10, 11, 168, 167, 166, 34, 14, 15,
	163, 160, 159, 158, 157, 151, 135, 129, 128, 127,
	122, 126, 121, 119, 103, 107, 100, 99, 98, 97,
	77, 35, 32, 20, 16, 1, 152, 123, 104, 23,
	21, 136, 50, 49, 48, 47, 46, 45, 44, 43,
	42, 41, 39, 40, 38, 6, 7, 2, 118, 8,
	5,
}
var ZFPPact = [...]int{

	-1000, -1000, 136, -1000, -1000, -1000, 3, 3, 3, 170,
	58, 169, -1000, 105, -1000, -1000, 44, 50, 15, 49,
	168, 8, -1000, 167, 102, 96, 166, 56, -1000, -1000,
	-1000, -1000, 13, -1000, -1000, -1000, 11, 6, 131, 126,
	129, 124, 122, 120, 118, 116, 114, 112, 110, 108,
	46, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, 165, 164, 163, 162, 101, 160,
	32, 161, 160, 160, 100, 45, 41, 12, 10, 48,
	30, -1000, 159, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, 9, -1000, -1000,
	-1000, 158, 156, -1000, 25, -1000, -1000, 157, 156, 156,
	155, 154, 153, 96, -1000, -1000, -1000, -1000, 26, 152,
	83, 151, -1000, 57, -1000, -1000, 150, 149, 148, 147,
	5, 29, -1000, -1000, -1000, 146, 2, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000, 142, -1000, -1000, -1000, -1000, -1000, -1000, -1000,
	141, -1000, -1000, -1000, -1000, -1000, -1000, 140, -1000,
}
var ZFPPgo = [...]int{

	0, 200, 199, 198, 197, 2, 196, 89, 3, 1,
	195, 5, 194, 193, 192, 191, 190, 189, 188, 187,
	186, 185, 184, 183, 182, 38, 27, 36, 33, 26,
	30, 28, 24, 25, 23, 8, 9, 7, 181, 0,
	140, 180, 125, 179, 6, 178, 177, 176, 175,
}
var ZFPR1 = [...]int{

	0, 48, 4, 4, 4, 4, 1, 1, 2, 3,
	3, 3, 5, 5, 6, 6, 7, 7, 7, 7,
	8, 8, 9, 9, 10, 10, 11, 11, 11, 11,
	11, 11, 11, 11, 11, 11, 11, 11, 11, 12,
	12, 25, 38, 38, 39, 39, 39, 39, 39, 39,
	39, 39, 39, 39, 39, 39, 39, 14, 14, 27,
	13, 13, 26, 15, 15, 28, 16, 16, 29, 17,
	17, 30, 18, 18, 31, 19, 19, 32, 20, 20,
	33, 21, 21, 34, 22, 22, 35, 23, 23, 36,
	24, 24, 37, 45, 45, 46, 46, 47, 47, 47,
	47, 44, 44, 40, 41, 41, 42, 42, 43,
}
var ZFPR2 = [...]int{

	0, 1, 0, 2, 2, 2, 1, 2, 6, 0,
	2, 2, 1, 2, 7, 5, 2, 2, 2, 2,
	0, 2, 1, 2, 5, 7, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 5, 1, 2, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 2, 2,
	1, 2, 2, 1, 2, 2, 1, 2, 4, 1,
	2, 2, 1, 2, 5, 1, 2, 4, 1, 2,
	2, 1, 2, 2, 1, 2, 4, 1, 2, 4,
	1, 2, 6, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 3, 1, 2, 1, 2, 6,
}
var ZFPChk = [...]int{

	-1000, -48, -4, -9, -5, -1, -10, -6, -2, 5,
	6, 7, -40, 36, -40, -40, 4, 4, -7, 32,
	4, -41, -42, -43, 21, 34, 4, 4, 33, 34,
	4, 33, 4, 37, -42, 4, 22, -11, -12, -14,
	-13, -15, -16, -17, -18, -19, -20, -21, -22, -23,
	-24, -25, -27, -26, -28, -29, -30, -31, -32, -33,
	-34, -35, -36, -37, 8, 10, 9, 11, 12, 13,
	14, 15, 16, 17, 18, 19, 20, 4, -7, 4,
	-8, 34, 31, 35, -25, -27, -26, -28, -29, -30,
	-31, -32, -33, -34, -35, -36, -37, 4, 4, 4,
	4, 22, -44, 4, -45, 23, 24, 4, -44, -44,
	22, 22, 22, 34, 34, 4, 35, -9, -3, 4,
	34, 4, 4, -46, 25, 26, 4, 4, 4, 4,
	-11, -8, 35, -9, -5, 4, -38, -39, 8, 9,
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	20, 4, -47, 27, 28, 29, 30, 4, 4, 4,
	4, 35, 35, 4, 35, -39, 4, 4, 4,
}
var ZFPDef = [...]int{

	2, -2, 1, 3, 4, 5, 22, 12, 6, 0,
	0, 0, 23, 0, 13, 7, 0, 0, 0, 0,
	0, 0, 104, 106, 0, 0, 0, 16, 18, 20,
	17, 19, 0, 103, 105, 107, 0, 0, 26, 27,
	28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
	38, 39, 57, 60, 63, 66, 69, 72, 75, 78,
	81, 84, 87, 90, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 9, 0, 24, 40, 58, 61, 64, 67, 70,
	73, 76, 79, 82, 85, 88, 91, 0, 59, 62,
	65, 0, 71, 101, 0, 93, 94, 0, 80, 83,
	0, 0, 0, 0, 20, 16, 15, 21, 0, 0,
	0, 0, 102, 0, 95, 96, 0, 0, 0, 0,
	0, 0, 8, 10, 11, 0, 0, 42, 44, 45,
	46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
	56, 68, 0, 97, 98, 99, 100, 77, 86, 89,
	0, 25, 14, 108, 41, 43, 74, 0, 92,
}
var ZFPTok1 = [...]int{

	1,
}
var ZFPTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37,
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
	//start CFE
	Result() []rainslib.MessageSectionWithSigForward
	//end CFE
}

type ZFPParserImpl struct {
	lval  ZFPSymType
	stack [ZFPInitialStackSize]ZFPSymType
	char  int
}

func (p *ZFPParserImpl) Lookahead() int {
	return p.char
}

//start CFE
func (p *ZFPParserImpl) Result() []rainslib.MessageSectionWithSigForward {
	return output
}

//end CFE

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
		//line zonefileParser.y:183
		{
			output = ZFPDollar[1].sections
		}
	case 2:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:188
		{
			ZFPVAL.sections = nil
		}
	case 3:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:192
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].assertion)
		}
	case 4:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:196
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].shard)
		}
	case 5:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:200
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].zone)
		}
	case 7:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:206
		{
			AddSigs(ZFPDollar[1].zone, ZFPDollar[2].signatures)
			ZFPVAL.zone = ZFPDollar[1].zone
		}
	case 8:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:212
		{
			ZFPVAL.zone = &rainslib.ZoneSection{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				Content:     ZFPDollar[5].sections,
			}
		}
	case 9:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:221
		{
			ZFPVAL.sections = nil
		}
	case 10:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:225
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].assertion)
		}
	case 11:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:229
		{
			ZFPVAL.sections = append(ZFPDollar[1].sections, ZFPDollar[2].shard)
		}
	case 13:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:235
		{
			AddSigs(ZFPDollar[1].shard, ZFPDollar[2].signatures)
			ZFPVAL.shard = ZFPDollar[1].shard
		}
	case 14:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:241
		{
			ZFPVAL.shard = &rainslib.ShardSection{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				RangeFrom:   ZFPDollar[4].shardRange[0],
				RangeTo:     ZFPDollar[4].shardRange[1],
				Content:     ZFPDollar[6].assertions,
			}
		}
	case 15:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:251
		{
			ZFPVAL.shard = &rainslib.ShardSection{
				RangeFrom: ZFPDollar[2].shardRange[0],
				RangeTo:   ZFPDollar[2].shardRange[1],
				Content:   ZFPDollar[4].assertions,
			}
		}
	case 16:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:260
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ZFPDollar[2].str}
		}
	case 17:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:264
		{
			ZFPVAL.shardRange = []string{"<", ZFPDollar[2].str}
		}
	case 18:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:268
		{
			ZFPVAL.shardRange = []string{ZFPDollar[1].str, ">"}
		}
	case 19:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:272
		{
			ZFPVAL.shardRange = []string{"<", ">"}
		}
	case 20:
		ZFPDollar = ZFPS[ZFPpt-0 : ZFPpt+1]
		//line zonefileParser.y:277
		{
			ZFPVAL.assertions = nil
		}
	case 21:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:281
		{
			ZFPVAL.assertions = append(ZFPDollar[1].assertions, ZFPDollar[2].assertion)
		}
	case 23:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:287
		{
			AddSigs(ZFPDollar[1].assertion, ZFPDollar[2].signatures)
			ZFPVAL.assertion = ZFPDollar[1].assertion
		}
	case 24:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:293
		{
			ZFPVAL.assertion = &rainslib.AssertionSection{
				SubjectName: ZFPDollar[2].str,
				Content:     ZFPDollar[4].objects,
			}
		}
	case 25:
		ZFPDollar = ZFPS[ZFPpt-7 : ZFPpt+1]
		//line zonefileParser.y:300
		{
			ZFPVAL.assertion = &rainslib.AssertionSection{
				SubjectZone: ZFPDollar[2].str,
				Context:     ZFPDollar[3].str,
				SubjectName: ZFPDollar[4].str,
				Content:     ZFPDollar[6].objects,
			}
		}
	case 39:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:324
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 40:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:328
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 41:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:333
		{
			ZFPVAL.object = rainslib.Object{
				Type: rainslib.OTName,
				Value: rainslib.NameObject{
					Name:  ZFPDollar[2].str,
					Types: ZFPDollar[4].objectTypes,
				},
			}
		}
	case 42:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:344
		{
			ZFPVAL.objectTypes = []rainslib.ObjectType{ZFPDollar[1].objectType}
		}
	case 43:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:348
		{
			ZFPVAL.objectTypes = append(ZFPDollar[1].objectTypes, ZFPDollar[2].objectType)
		}
	case 44:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:353
		{
			ZFPVAL.objectType = rainslib.OTName
		}
	case 45:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:357
		{
			ZFPVAL.objectType = rainslib.OTIP4Addr
		}
	case 46:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:361
		{
			ZFPVAL.objectType = rainslib.OTIP6Addr
		}
	case 47:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:365
		{
			ZFPVAL.objectType = rainslib.OTRedirection
		}
	case 48:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:369
		{
			ZFPVAL.objectType = rainslib.OTDelegation
		}
	case 49:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:373
		{
			ZFPVAL.objectType = rainslib.OTNameset
		}
	case 50:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:377
		{
			ZFPVAL.objectType = rainslib.OTCertInfo
		}
	case 51:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:381
		{
			ZFPVAL.objectType = rainslib.OTServiceInfo
		}
	case 52:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:385
		{
			ZFPVAL.objectType = rainslib.OTRegistrar
		}
	case 53:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:389
		{
			ZFPVAL.objectType = rainslib.OTRegistrant
		}
	case 54:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:393
		{
			ZFPVAL.objectType = rainslib.OTInfraKey
		}
	case 55:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:397
		{
			ZFPVAL.objectType = rainslib.OTExtraKey
		}
	case 56:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:401
		{
			ZFPVAL.objectType = rainslib.OTNextKey
		}
	case 57:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:406
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 58:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:410
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 59:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:415
		{
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTIP6Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 60:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:423
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 61:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:427
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 62:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:432
		{
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTIP4Addr,
				Value: ZFPDollar[2].str,
			}
		}
	case 63:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:440
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 64:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:444
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 65:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:449
		{
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTRedirection,
				Value: ZFPDollar[2].str,
			}
		}
	case 66:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:457
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 67:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:461
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 68:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:466
		{
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTDelegation,
				Value: pkey,
			}
		}
	case 69:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:478
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 70:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:482
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 71:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:487
		{
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTNameset,
				Value: ZFPDollar[2].str,
			}
		}
	case 72:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:495
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 73:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:499
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 74:
		ZFPDollar = ZFPS[ZFPpt-5 : ZFPpt+1]
		//line zonefileParser.y:504
		{
			cert, err := DecodeCertificate(ZFPDollar[2].protocolType, ZFPDollar[3].certUsage, ZFPDollar[4].hashType, ZFPDollar[5].str)
			if err != nil {
				log.Error("semantic error:", "Decode certificate", err)
			}
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTCertInfo,
				Value: cert,
			}
		}
	case 75:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:516
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 76:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:520
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 77:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:525
		{
			srv, err := DecodeSrv(ZFPDollar[2].str, ZFPDollar[3].str, ZFPDollar[4].str)
			if err != nil {
				log.Error("semantic error:", "error", err)
			}
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTServiceInfo,
				Value: srv,
			}
		}
	case 78:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:537
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 79:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:541
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 80:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:546
		{
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTRegistrar,
				Value: ZFPDollar[2].str,
			}
		}
	case 81:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:554
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 82:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:558
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 83:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:563
		{
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTRegistrant,
				Value: ZFPDollar[2].str,
			}
		}
	case 84:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:571
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 85:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:575
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 86:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:580
		{
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTInfraKey,
				Value: pkey,
			}
		}
	case 87:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:592
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 88:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:596
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 89:
		ZFPDollar = ZFPS[ZFPpt-4 : ZFPpt+1]
		//line zonefileParser.y:601
		{ //TODO CFE as of now there is only the rains key space. There will
			//be additional rules in case there are new key spaces
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTExtraKey,
				Value: pkey,
			}
		}
	case 90:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:614
		{
			ZFPVAL.objects = []rainslib.Object{ZFPDollar[1].object}
		}
	case 91:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:618
		{
			ZFPVAL.objects = append(ZFPDollar[1].objects, ZFPDollar[2].object)
		}
	case 92:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:623
		{
			pkey, err := DecodeEd25519PublicKeyData(ZFPDollar[4].str, ZFPDollar[3].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
			}
			pkey.ValidSince, pkey.ValidUntil, err = DecodeValidity(ZFPDollar[5].str, ZFPDollar[6].str)
			if err != nil {
				log.Error("semantic error:", "error", err)
			}
			ZFPVAL.object = rainslib.Object{
				Type:  rainslib.OTNextKey,
				Value: pkey,
			}
		}
	case 93:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:639
		{
			ZFPVAL.protocolType = rainslib.PTUnspecified
		}
	case 94:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:643
		{
			ZFPVAL.protocolType = rainslib.PTTLS
		}
	case 95:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:648
		{
			ZFPVAL.certUsage = rainslib.CUTrustAnchor
		}
	case 96:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:652
		{
			ZFPVAL.certUsage = rainslib.CUEndEntity
		}
	case 97:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:657
		{
			ZFPVAL.hashType = rainslib.NoHashAlgo
		}
	case 98:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:661
		{
			ZFPVAL.hashType = rainslib.Sha256
		}
	case 99:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:665
		{
			ZFPVAL.hashType = rainslib.Sha384
		}
	case 100:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:669
		{
			ZFPVAL.hashType = rainslib.Sha512
		}
	case 102:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:675
		{
			ZFPVAL.str = ZFPDollar[1].str + " " + ZFPDollar[2].str
		}
	case 103:
		ZFPDollar = ZFPS[ZFPpt-3 : ZFPpt+1]
		//line zonefileParser.y:680
		{
			ZFPVAL.signatures = ZFPDollar[2].signatures
		}
	case 104:
		ZFPDollar = ZFPS[ZFPpt-1 : ZFPpt+1]
		//line zonefileParser.y:685
		{
			ZFPVAL.signatures = []rainslib.Signature{ZFPDollar[1].signature}
		}
	case 105:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:689
		{
			ZFPVAL.signatures = append(ZFPDollar[1].signatures, ZFPDollar[2].signature)
		}
	case 107:
		ZFPDollar = ZFPS[ZFPpt-2 : ZFPpt+1]
		//line zonefileParser.y:695
		{
			data, err := DecodeEd25519SignatureData(ZFPDollar[2].str)
			if err != nil {
				log.Error("semantic error:", "DecodeEd25519SignatureData", err)
			}
			ZFPDollar[1].signature.Data = data
			ZFPVAL.signature = ZFPDollar[1].signature
		}
	case 108:
		ZFPDollar = ZFPS[ZFPpt-6 : ZFPpt+1]
		//line zonefileParser.y:705
		{
			publicKeyID, err := DecodePublicKeyID(ZFPDollar[4].str)
			if err != nil {
				log.Error("semantic error:", "DecodePublicKeyID", err)
			}
			validSince, validUntil, err := DecodeValidity(ZFPDollar[5].str, ZFPDollar[6].str)
			if err != nil {
				log.Error("semantic error:", "DecodeValidity", err)
			}
			ZFPVAL.signature = rainslib.Signature{
				PublicKeyID: publicKeyID,
				ValidSince:  validSince,
				ValidUntil:  validUntil,
			}
		}
	}
	goto ZFPstack /* stack new state and value */
}
