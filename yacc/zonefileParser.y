// To build it:
// goyacc -p "ZFP" zonefileParser.y (produces y.go)
// go build -o zonefileParser y.go
// run ./zonefileParser, the zonefile must be placed in the same directoy and
// must be called zonefile.txt

%{

package main

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

// DecodeEd25519PublicKeyData returns the publicKey or an error in case
// pkeyInput is malformed i.e. it is not in zone file format.
func DecodeEd25519PublicKeyData(pkeyInput string, keyphase string) (rainslib.PublicKey, error) {
	phase, err := strconv.Atoi(keyphase)
	if err != nil {
		return rainslib.PublicKey{}, errors.New("keyphase is not a number")
	}
	publicKeyID := rainslib.PublicKeyID{
		Algorithm: rainslib.Ed25519,
		KeyPhase:  phase,
		KeySpace:  rainslib.RainsKeySpace,
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
    if  err != nil || port < 0 || port > 65535 {
        return rainslib.ServiceInfo{}, errors.New("Port is not a number or out of range")
    }
    priority, err := strconv.Atoi(priorityString)
    if  err != nil || port < 0 {
        return rainslib.ServiceInfo{}, errors.New("Priority is not a number or negative")
    }
    return rainslib.ServiceInfo {
        Name: name,
        Port: uint16(port),
        Priority: uint(priority),
    }, nil
}

%}

// fields inside this union end up as the fields in a structure known
// as ${PREFIX}SymType, of which a reference is passed to the lexer.
%union{
    str             string
    assertion       *rainslib.AssertionSection
    assertions      []*rainslib.AssertionSection
    shard           *rainslib.ShardSection
    zone            *rainslib.ZoneSection
    sections        []rainslib.MessageSectionWithSigForward
    objects         []rainslib.Object
    object          rainslib.Object
    objectTypes     []rainslib.ObjectType
    objectType      rainslib.ObjectType
    signatures      []rainslib.Signature
    signature       rainslib.Signature
    shardRange      []string
    publicKey       rainslib.PublicKey
    protocolType    rainslib.ProtocolType
    certUsage       rainslib.CertificateUsage
    hashType        rainslib.HashAlgorithmType
}

// any non-terminal which returns a value needs a type, which must be a field 
// name in the above union struct
%type <zone>            zone
%type <sections>        zoneContent
%type <shard>           shard shardBody
%type <shardRange>      shardRange
%type <assertions>      shardContent
%type <assertion>       assertion assertionBody
%type <objects>         object name ip4 ip6 redir deleg nameset cert
%type <objects>         srv regr regt infra extra next
%type <object>          nameBody ip4Body ip6Body redirBody delegBody namesetBody certBody
%type <object>          srvBody regrBody regtBody infraBody extraBody nextBody
%type <objectTypes>     oTypes
%type <objectType>      oType
%type <signatures>      annotation annotationBody
%type <signature>       signature signatureMeta
%type <str>             freeText
%type <protocolType>    protocolType
%type <certUsage>       certUsage
%type <hashType>        hashType

// Terminals
%token <str> ID
// Section types
%token assertionType shardType zoneType
// Object types
%token nameType ip4Type ip6Type redirType delegType namesetType certType
%token srvType regrType regtType infraType extraType nextType
// Annotation types
%token sigType 
// Signature algorithm types
%token ed25519Type
// Certificate types
%token unspecified tls trustAnchor endEntity 
// Hash algorithm types
%token noHash sha256 sha384 sha512
// Special shard range markers
%token rangeBegin rangeEnd
// Special
%token lBracket rBracket lParenthesis rParenthesis

%% /* Grammer rules  */

top             : zone
                {
                    fmt.Printf("\n%s\n", $1.String())
                }
                | zone annotation
                {   
                    AddSigs($1,$2)
                    fmt.Printf("\n%s\n", $1.String())
                }

zone            : zoneType ID ID lBracket zoneContent rBracket
                {
                    $$ = &rainslib.ZoneSection{
                        SubjectZone: $2, 
                        Context: $3,
                        Content: $5,    
                    }
                }

zoneContent     : /* empty */
                {
                    $$ = nil
                }
                | zoneContent assertion
                {
                    $$ = append($1, $2)
                }
                | zoneContent shard
                {
                    $$ = append($1, $2)
                }

shard           : shardBody
                | shardBody annotation
                {
                    AddSigs($1,$2)
                    $$ = $1
                }

shardBody       : shardType ID ID shardRange lBracket shardContent rBracket
                {
                    $$ = &rainslib.ShardSection{
                        SubjectZone: $2, 
                        Context: $3,
                        RangeFrom: $4[0],
                        RangeTo: $4[1],
                        Content: $6,
                    }
                }
                | shardType shardRange lBracket shardContent rBracket
                {
                    $$ = &rainslib.ShardSection{
                        RangeFrom: $2[0],
                        RangeTo: $2[1],
                        Content: $4,
                    }
                }

shardRange      : ID ID
                {
                    $$ = []string{$1, $2}
                }
                | rangeBegin ID
                {
                    $$ = []string{"<", $2}
                }
                | ID rangeEnd
                {
                    $$ = []string{$1, ">"}
                }
                | rangeBegin rangeEnd
                {
                    $$ = []string{"<", ">"}
                }

shardContent :  /* empty */
                {
                    $$ = nil
                }
                | shardContent assertion
                {
                    $$ = append($1,$2)
                }

assertion       : assertionBody
                | assertionBody annotation
                {
                    AddSigs($1,$2)
                    $$ = $1
                }
    
assertionBody   : assertionType ID lBracket object rBracket
                {
                    $$ = &rainslib.AssertionSection{
                        SubjectName: $2,
                        Content: $4,
                    }
                }
                | assertionType ID ID ID lBracket object rBracket
                {
                    $$ = &rainslib.AssertionSection{
                        SubjectZone: $2, 
                        Context: $3,
                        SubjectName: $4,
                        Content: $6,
                    }
                }

object          : name
                | ip4
                | ip6
                | redir
                | deleg
                | nameset
                | cert
                | srv
                | regr
                | regt
                | infra
                | extra
                | next

name            : nameBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | name nameBody
                {
                    $$ = append($1,$2)
                }

nameBody        : nameType ID lBracket oTypes rBracket
                {
                    $$ = rainslib.Object{
                        Type: rainslib.OTName,
                        Value: rainslib.NameObject{
                            Name: $2,
                            Types: $4,
                        },
                    }
                }

oTypes          : oType
                {
                    $$ = []rainslib.ObjectType{$1}
                }
                | oTypes oType
                {
                    $$ = append($1,$2)
                }

oType           : nameType
                {
                    $$ = rainslib.OTName
                }
                | ip4Type
                {
                    $$ = rainslib.OTIP4Addr
                }
                | ip6Type
                {
                    $$ = rainslib.OTIP6Addr
                }
                | redirType
                {
                    $$ = rainslib.OTRedirection
                }
                | delegType
                {
                    $$ = rainslib.OTDelegation
                }
                | namesetType
                {
                    $$ = rainslib.OTNameset
                }
                | certType
                {
                    $$ = rainslib.OTCertInfo
                }
                | srvType
                {
                    $$ = rainslib.OTServiceInfo
                }
                | regrType
                {
                    $$ = rainslib.OTRegistrar
                }
                | regtType
                {
                    $$ = rainslib.OTRegistrant
                }
                | infraType
                {
                    $$ = rainslib.OTInfraKey
                }
                | extraType
                {
                    $$ = rainslib.OTExtraKey
                }
                | nextType
                {
                    $$ = rainslib.OTNextKey
                }

ip4             : ip4Body
                {
                    $$ = []rainslib.Object{$1}
                }
                | ip4 ip4Body
                {
                    $$ = append($1,$2)
                }

ip4Body         : ip4Type ID
                {
                    $$ = rainslib.Object{
                        Type: rainslib.OTIP4Addr,
                        Value: $2,
                    }
                }

ip6             : ip6Body
                {
                    $$ = []rainslib.Object{$1}
                }
                | ip6 ip6Body
                {
                    $$ = append($1,$2)
                }

ip6Body         : ip6Type ID
                {
                    $$ = rainslib.Object{
                        Type: rainslib.OTIP6Addr,
                        Value: $2,
                    }
                }

redir             : redirBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | redir redirBody
                {
                    $$ = append($1,$2)
                }

redirBody       : redirType ID
                {
                    $$ = rainslib.Object{
                        Type: rainslib.OTRedirection,
                        Value: $2,
                    }
                }

deleg           : delegBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | deleg delegBody
                {
                    $$ = append($1,$2)
                }

delegBody       : delegType ed25519Type ID ID
                {
                    pkey, err := DecodeEd25519PublicKeyData($4, $3)
                    if  err != nil {
                        log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
                    }
                    $$ = rainslib.Object{
                        Type: rainslib.OTDelegation,
                        Value: pkey,
                    }
                }

nameset         : namesetBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | nameset namesetBody
                {
                    $$ = append($1,$2)
                }

namesetBody     : namesetType freeText
                {
                    $$ = rainslib.Object{
                        Type: rainslib.OTNameset,
                        Value: $2,
                    }
                }

cert            : certBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | cert certBody
                {
                    $$ = append($1,$2)
                }

certBody :      certType protocolType certUsage hashType ID
                {
                    cert, err := DecodeCertificate($2,$3,$4,$5)
                    if err != nil {
                        log.Error("semantic error:", "Decode certificate", err)
                    }
                    $$ = rainslib.Object{
                        Type: rainslib.OTCertInfo,
                        Value: cert,
                    }
                }

srv             : srvBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | srv srvBody
                {
                    $$ = append($1,$2)
                }

srvBody         : srvType ID ID ID
                {
                    srv, err := DecodeSrv($2,$3,$4)
                    if err != nil {
                        log.Error("semantic error:", "error", err)
                    }
                    $$ = rainslib.Object{
                        Type: rainslib.OTServiceInfo,
                        Value: srv,
                    }
                }

regr            : regrBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | regr regrBody
                {
                    $$ = append($1,$2)
                }

regrBody        : regrType freeText
                {
                    $$ = rainslib.Object{
                        Type: rainslib.OTRegistrar,
                        Value: $2,
                    }
                }

regt            : regtBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | regt regtBody
                {
                    $$ = append($1,$2)
                }

regtBody        : regtType freeText
                {
                    $$ = rainslib.Object{
                        Type: rainslib.OTRegistrant,
                        Value: $2,
                    }
                }

infra           : infraBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | infra infraBody
                {
                    $$ = append($1,$2)
                }

infraBody       : infraType ed25519Type ID ID
                {
                    pkey, err := DecodeEd25519PublicKeyData($4, $3)
                    if  err != nil {
                        log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
                    }
                    $$ = rainslib.Object{
                        Type: rainslib.OTInfraKey,
                        Value: pkey,
                    }
                }

extra           : extraBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | extra extraBody
                {
                    $$ = append($1,$2)
                }

extraBody       : extraType ed25519Type ID ID
                {   //TODO CFE as of now there is only the rains key space. There will
                    //be additional rules in case there are new key spaces 
                    pkey, err := DecodeEd25519PublicKeyData($4, $3)
                    if  err != nil {
                        log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
                    }
                    $$ = rainslib.Object{
                        Type: rainslib.OTExtraKey,
                        Value: pkey,
                    }
                }

next            : nextBody
                {
                    $$ = []rainslib.Object{$1}
                }
                | next nextBody
                {
                    $$ = append($1,$2)
                }

nextBody        : nextType ed25519Type ID ID ID ID
                {
                    pkey, err := DecodeEd25519PublicKeyData($4, $3)
                    if  err != nil {
                        log.Error("semantic error:", "DecodeEd25519PublicKeyData", err)
                    }
                    pkey.ValidSince, err = strconv.ParseInt($5, 10, 64)
                    if  err != nil || pkey.ValidSince < 0 {
                        log.Error("semantic error:", "error", "validSince is not a number or negative")
                    }
                    pkey.ValidUntil, err = strconv.ParseInt($6, 10, 64)
                    if  err != nil || pkey.ValidUntil < 0 {
                        log.Error("semantic error:", "error", "validUntil is not a number or negative")
                    }
                    $$ = rainslib.Object{
                                            Type: rainslib.OTNextKey,
                                            Value: pkey,
                    }
                }

protocolType    : unspecified
                {
                    $$ = rainslib.PTUnspecified
                }
                | tls
                {
                    $$ = rainslib.PTTLS
                }

certUsage       : trustAnchor
                {
                    $$ = rainslib.CUTrustAnchor
                }
                | endEntity
                {
                    $$ = rainslib.CUEndEntity
                }

hashType        : noHash
                {
                    $$ = rainslib.NoHashAlgo
                }
                | sha256
                {
                    $$ = rainslib.Sha256
                }
                | sha384
                {
                    $$ = rainslib.Sha384
                }
                | sha512
                {
                    $$ = rainslib.Sha512
                }

freeText        : ID
                | freeText ID
                {
                    $$ = $1 + " " + $2
                }

annotation      : lParenthesis annotationBody rParenthesis
                {
                    $$ = $2
                }

annotationBody  : signature
                {
                    $$ = []rainslib.Signature{$1}
                }
                | annotationBody signature
                {
                    $$ = append($1, $2)
                }

signature       : signatureMeta
                | signatureMeta ID
                {   
                    //TODO CFE add actual signature to Signature struct
                    $$ = rainslib.Signature{}
                }

signatureMeta   : sigType ed25519Type ID ID ID ID
                {
                    //TODO CFE complicated, lot of casting -> make tokens
                    $$ = rainslib.Signature{ValidSince: 5}
                }

%%      /*  Lexer  */

// The parser expects the lexer to return 0 on EOF.  Give it a name
// for clarity.
const eof = 0

type ZFPLex struct {
	lines       [][]string
    lineNr      int
    linePos     int
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
	case ":A:" :
        return assertionType
    case ":S:" :
        return shardType
    case ":Z:" :
        return zoneType
    case ":name:" :
		return nameType
	case ":ip6:" :
		return ip6Type
	case ":ip4:" :
		return ip4Type
	case ":redir:" :
		return redirType
	case ":deleg:" :
		return delegType
	case ":nameset:" :
		return namesetType
	case ":cert:" :
		return certType
	case ":srv:" :
		return srvType
	case ":regr:" :
		return regrType
	case ":regt:" :
		return regtType
	case ":infra:" :
		return infraType
	case ":extra:" :
		return extraType
	case ":next:" :
		return nextType
    case ":sig:" :
        return sigType
    case ":ed25519:" :
        return ed25519Type
    case ":unspecified:" :
        return unspecified
    case ":tls:" :
        return tls
    case ":trustAnchor:" :
        return trustAnchor
    case ":endEntity:" :
        return endEntity
    case ":noHash:" :
        return noHash
    case ":sha256:" :
        return sha256
    case ":sha384:" :
        return sha384
    case ":sha512:" :
        return sha512
    case "<" :
        return rangeBegin
    case ">" :
        return rangeEnd
    case "[" :
        return lBracket
    case "]" :
        return rBracket
    case "(" :
        return lParenthesis
    case ")" :
        return rParenthesis
	default :
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