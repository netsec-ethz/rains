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
    "github.com/netsec-ethz/rains/internal/pkg/signature"
    "github.com/netsec-ethz/rains/internal/pkg/section"
    "github.com/netsec-ethz/rains/internal/pkg/object"
    "github.com/netsec-ethz/rains/internal/pkg/keys"
    "github.com/netsec-ethz/rains/internal/pkg/zonefile"
    "github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
    "github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
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
            HashFamily: hashAlgos,
            NofHashFunctions: funcs,
            ModeOfOperation: modeOfOperation,
            Filter: bitarray.BitArray(decodedFilter),
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
    if  err != nil || port < 0 || port > 65535 {
        return object.ServiceInfo{}, errors.New("Port is not a number or out of range")
    }
    priority, err := strconv.Atoi(priorityString)
    if  err != nil || port < 0 {
        return object.ServiceInfo{}, errors.New("Priority is not a number or negative")
    }
    return object.ServiceInfo {
        Name: name,
        Port: uint16(port),
        Priority: uint(priority),
    }, nil
}

func DecodeValidity(validSince, validUntil string) (int64, int64, error) {
    vsince, err := strconv.ParseInt(validSince, 10, 64)
    if  err != nil || vsince < 0 {
        return 0,0, errors.New("validSince is not a number or negative")
    }
    vuntil, err := strconv.ParseInt(validUntil, 10, 64)
    if  err != nil || vuntil < 0 {
        return 0,0, errors.New("validUntil is not a number or negative")
    }
    return vsince, vuntil, nil
}

//Result gets stored in this variable
var output []section.WithSigForward

%}


// fields inside this union end up as the fields in a structure known
// as ${PREFIX}SymType, of which a reference is passed to the lexer.
%union{
    str             string
    assertion       *section.Assertion
    assertions      []*section.Assertion
    shard           *section.Shard
    pshard          *section.Pshard
    zone            *section.Zone
    sections        []section.WithSigForward
    objects         []object.Object
    object          object.Object
    objectTypes     []object.Type
    objectType      object.Type
    signatures      []signature.Sig
    signature       signature.Sig
    shardRange      []string
    publicKey       keys.PublicKey
    protocolType    object.ProtocolType
    certUsage       object.CertificateUsage
    hashType        algorithmTypes.Hash
    hashTypes       []algorithmTypes.Hash
    dataStructure   section.DataStructure
    bfOpMode        section.ModeOfOperationType
}

// any non-terminal which returns a value needs a type, which must be a field 
// name in the above union struct
%type <zone>            zone zoneBody
%type <sections>        sections
%type <shard>           shard shardBody
%type <shardRange>      shardRange
%type <pshard>          pshard pshardBody
%type <dataStructure>   pshardContent bloomFilter
%type <assertions>      shardContent zoneContent
%type <assertion>       assertion assertionBody
%type <objects>         objects name ip4 ip6 redir deleg nameset cert
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
%type <hashTypes>       hashTypes
%type <hashType>        hashType
%type <bfOpMode>        bfOpMode

// Terminals
%token <str> ID
// Section types
%token assertionType shardType pshardType zoneType
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
%token noHash sha256 sha384 sha512 shake256 fnv64 fnv128
// Data structure types
%token bloomFilterType
// Bloom filter mode of operations
%token standard km1 km2
// Key spaces
%token rains
// Special shard range markers
%token rangeBegin rangeEnd
// Special
%token lBracket rBracket lParenthesis rParenthesis

%% /* Grammer rules  */

top             : sections
                {
                    output = $1
                }

sections        : /* empty */
                {
                    $$ = nil
                }
                | sections assertion
                {
                    $$ = append($1, $2)
                }
                | sections shard
                {
                    $$ = append($1, $2)
                }
                | sections pshard
                {
                    $$ = append($1, $2)
                }
                | sections zone
                {
                    $$ = append($1, $2)
                }

zone            : zoneBody
                | zoneBody annotation
                {
                    AddSigs($1,$2)
                    $$ = $1
                }

zoneBody        : zoneType ID ID lBracket zoneContent rBracket
                {
                    $$ = &section.Zone{
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

shard           : shardBody
                | shardBody annotation
                {
                    AddSigs($1,$2)
                    $$ = $1
                }

shardBody       : shardType ID ID shardRange lBracket shardContent rBracket
                {
                    $$ = &section.Shard{
                        SubjectZone: $2, 
                        Context: $3,
                        RangeFrom: $4[0],
                        RangeTo: $4[1],
                        Content: $6,
                    }
                }
                | shardType shardRange lBracket shardContent rBracket
                {
                    $$ = &section.Shard{
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

pshard          : pshardBody
                | pshardBody annotation
                {
                    AddSigs($1,$2)
                    $$ = $1
                }

pshardBody      : pshardType ID ID shardRange pshardContent
                {
                    $$ = &section.Pshard{
                        SubjectZone: $2, 
                        Context: $3,
                        RangeFrom: $4[0],
                        RangeTo: $4[1],
                        Datastructure: $5,
                    }
                }
                | pshardType shardRange pshardContent
                {
                    $$ = &section.Pshard{
                        RangeFrom: $2[0],
                        RangeTo: $2[1],
                        Datastructure: $3,
                    }
                }

pshardContent   : bloomFilter

bloomFilter     : bloomFilterType lBracket hashTypes rBracket ID bfOpMode ID
                {
                    bloomFilter, err := DecodeBloomFilter($3, $6, $5,$7)
                    if  err != nil {
                        log.Error("semantic error:", "DecodeBloomFilter", err)
                    }
                    $$ = section.DataStructure{
                        Type: section.BloomFilterType,
                        Data: bloomFilter,
                    }
                }

hashTypes       : hashType
                {
                    $$ = []algorithmTypes.Hash{$1}
                }
                | hashTypes hashType
                {
                    $$ = append($1,$2)
                }

bfOpMode        : standard
                {
                    $$ = section.StandardOpType
                }
                | km1
                {
                    $$ = section.KirschMitzenmacher1
                }
                | km2
                {
                    $$ = section.KirschMitzenmacher2
                }

assertion       : assertionBody
                | assertionBody annotation
                {
                    AddSigs($1,$2)
                    $$ = $1
                }
    
assertionBody   : assertionType ID lBracket objects rBracket
                {
                    $$ = &section.Assertion{
                        SubjectName: $2,
                        Content: $4,
                    }
                }
                | assertionType ID ID ID lBracket objects rBracket
                {
                    $$ = &section.Assertion{
                        SubjectName: $2,
                        SubjectZone: $3, 
                        Context: $4,
                        Content: $6,
                    }
                }

objects          : name
                | ip6
                | ip4
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
                    $$ = []object.Object{$1}
                }
                | name nameBody
                {
                    $$ = append($1,$2)
                }

nameBody        : nameType ID lBracket oTypes rBracket
                {
                    $$ = object.Object{
                        Type: object.OTName,
                        Value: object.Name{
                            Name: $2,
                            Types: $4,
                        },
                    }
                }

oTypes          : oType
                {
                    $$ = []object.Type{$1}
                }
                | oTypes oType
                {
                    $$ = append($1,$2)
                }

oType           : nameType
                {
                    $$ = object.OTName
                }
                | ip4Type
                {
                    $$ = object.OTIP4Addr
                }
                | ip6Type
                {
                    $$ = object.OTIP6Addr
                }
                | redirType
                {
                    $$ = object.OTRedirection
                }
                | delegType
                {
                    $$ = object.OTDelegation
                }
                | namesetType
                {
                    $$ = object.OTNameset
                }
                | certType
                {
                    $$ = object.OTCertInfo
                }
                | srvType
                {
                    $$ = object.OTServiceInfo
                }
                | regrType
                {
                    $$ = object.OTRegistrar
                }
                | regtType
                {
                    $$ = object.OTRegistrant
                }
                | infraType
                {
                    $$ = object.OTInfraKey
                }
                | extraType
                {
                    $$ = object.OTExtraKey
                }
                | nextType
                {
                    $$ = object.OTNextKey
                }

ip6             : ip6Body
                {
                    $$ = []object.Object{$1}
                }
                | ip6 ip6Body
                {
                    $$ = append($1,$2)
                }

ip6Body         : ip6Type ID
                {
                    $$ = object.Object{
                        Type: object.OTIP6Addr,
                        Value: $2,
                    }
                }

ip4             : ip4Body
                {
                    $$ = []object.Object{$1}
                }
                | ip4 ip4Body
                {
                    $$ = append($1,$2)
                }

ip4Body         : ip4Type ID
                {
                    $$ = object.Object{
                        Type: object.OTIP4Addr,
                        Value: $2,
                    }
                }

redir             : redirBody
                {
                    $$ = []object.Object{$1}
                }
                | redir redirBody
                {
                    $$ = append($1,$2)
                }

redirBody       : redirType ID
                {
                    $$ = object.Object{
                        Type: object.OTRedirection,
                        Value: $2,
                    }
                }

deleg           : delegBody
                {
                    $$ = []object.Object{$1}
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
                    $$ = object.Object{
                        Type: object.OTDelegation,
                        Value: pkey,
                    }
                }

nameset         : namesetBody
                {
                    $$ = []object.Object{$1}
                }
                | nameset namesetBody
                {
                    $$ = append($1,$2)
                }

namesetBody     : namesetType freeText
                {
                    $$ = object.Object{
                        Type: object.OTNameset,
                        Value: $2,
                    }
                }

cert            : certBody
                {
                    $$ = []object.Object{$1}
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
                    $$ = object.Object{
                        Type: object.OTCertInfo,
                        Value: cert,
                    }
                }

srv             : srvBody
                {
                    $$ = []object.Object{$1}
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
                    $$ = object.Object{
                        Type: object.OTServiceInfo,
                        Value: srv,
                    }
                }

regr            : regrBody
                {
                    $$ = []object.Object{$1}
                }
                | regr regrBody
                {
                    $$ = append($1,$2)
                }

regrBody        : regrType freeText
                {
                    $$ = object.Object{
                        Type: object.OTRegistrar,
                        Value: $2,
                    }
                }

regt            : regtBody
                {
                    $$ = []object.Object{$1}
                }
                | regt regtBody
                {
                    $$ = append($1,$2)
                }

regtBody        : regtType freeText
                {
                    $$ = object.Object{
                        Type: object.OTRegistrant,
                        Value: $2,
                    }
                }

infra           : infraBody
                {
                    $$ = []object.Object{$1}
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
                    $$ = object.Object{
                        Type: object.OTInfraKey,
                        Value: pkey,
                    }
                }

extra           : extraBody
                {
                    $$ = []object.Object{$1}
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
                    $$ = object.Object{
                        Type: object.OTExtraKey,
                        Value: pkey,
                    }
                }

next            : nextBody
                {
                    $$ = []object.Object{$1}
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
                    pkey.ValidSince, pkey.ValidUntil, err = DecodeValidity($5,$6)
                    if  err != nil {
                        log.Error("semantic error:", "error", err)
                    }
                    $$ = object.Object{
                        Type: object.OTNextKey,
                        Value: pkey,
                    }
                }

protocolType    : unspecified
                {
                    $$ = object.PTUnspecified
                }
                | tls
                {
                    $$ = object.PTTLS
                }

certUsage       : trustAnchor
                {
                    $$ = object.CUTrustAnchor
                }
                | endEntity
                {
                    $$ = object.CUEndEntity
                }

hashType        : noHash
                {
                    $$ = algorithmTypes.NoHashAlgo
                }
                | sha256
                {
                    $$ = algorithmTypes.Sha256
                }
                | sha384
                {
                    $$ = algorithmTypes.Sha384
                }
                | sha512
                {
                    $$ = algorithmTypes.Sha512
                }
                | shake256
                {
                    $$ = algorithmTypes.Shake256
                }
                | fnv64
                {
                    $$ = algorithmTypes.Fnv64
                }
                | fnv128
                {
                    $$ = algorithmTypes.Fnv128
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
                    $$ = []signature.Sig{$1}
                }
                | annotationBody signature
                {
                    $$ = append($1, $2)
                }

signature       : signatureMeta
                | signatureMeta ID
                {   
                    data, err := DecodeEd25519SignatureData($2)
                    if  err != nil {
                        log.Error("semantic error:", "DecodeEd25519SignatureData", err)
                    }
                    $1.Data = data
                    $$ = $1
                }

signatureMeta   : sigType ed25519Type rains ID ID ID
                {
                    publicKeyID, err := DecodePublicKeyID($4)
                    if  err != nil {
                        log.Error("semantic error:", "DecodePublicKeyID", err)
                    }
                    validSince, validUntil, err := DecodeValidity($5,$6)
                    if  err != nil {
                        log.Error("semantic error:", "DecodeValidity", err)
                    }
                    $$ = signature.Sig{
                        PublicKeyID: publicKeyID,
                        ValidSince: validSince,
                        ValidUntil: validUntil,
                    }
                }

%%      /*  Lexer  */

// The parser expects the lexer to return 0 on EOF.
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
	case zonefile.TypeAssertion :
        return assertionType
    case zonefile.TypeShard :
        return shardType
    case zonefile.TypePshard :
        return pshardType
    case zonefile.TypeZone :
        return zoneType
    case zonefile.TypeName :
		return nameType
	case zonefile.TypeIP6 :
		return ip6Type
	case zonefile.TypeIP4 :
		return ip4Type
	case zonefile.TypeRedirection :
		return redirType
	case zonefile.TypeDelegation :
		return delegType
	case zonefile.TypeNameSet :
		return namesetType
	case zonefile.TypeCertificate :
		return certType
	case zonefile.TypeServiceInfo :
		return srvType
	case zonefile.TypeRegistrar :
		return regrType
	case zonefile.TypeRegistrant :
		return regtType
	case zonefile.TypeInfraKey :
		return infraType
	case zonefile.TypeExternalKey :
		return extraType
	case zonefile.TypeNextKey :
		return nextType
    case zonefile.TypeSignature :
        return sigType
    case zonefile.TypeEd25519 :
        return ed25519Type
    case zonefile.TypeUnspecified :
        return unspecified
    case zonefile.TypePTTLS :
        return tls
    case zonefile.TypeCUTrustAnchor :
        return trustAnchor
    case zonefile.TypeCUEndEntity :
        return endEntity
    case zonefile.TypeNoHash :
        return noHash
    case zonefile.TypeSha256 :
        return sha256
    case zonefile.TypeSha384 :
        return sha384
    case zonefile.TypeSha512 :
        return sha512
    case zonefile.TypeShake256 :
        return shake256
    case zonefile.TypeFnv64 :
        return fnv64
    case zonefile.TypeFnv128 :
        return fnv128
    case zonefile.TypeBloomFilter :
        return bloomFilterType
    case zonefile.TypeStandard :
        return standard
    case zonefile.TypeKM1 :
        return km1
    case zonefile.TypeKM2 :
        return km2
    case zonefile.TypeKSRains :
        return rains
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