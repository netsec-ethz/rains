// To build it:
// goyacc -p "ZFP" zonefileParser.y (produces y.go)
// go build -o zonefileParser y.go
// run ./zonefileParser, the zonefile must be placed in the same directoy and
// must be called zonefile.txt

%{

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
    "bytes"
    "strings"
    log "github.com/inconshreveable/log15"
    "github.com/netsec-ethz/rains/rainslib"
)

var regs = make([]int, 26)
var base int

%}

// fields inside this union end up as the fields in a structure known
// as ${PREFIX}SymType, of which a reference is passed to the lexer.
%union{
    str string
    assertion *rainslib.AssertionSection
    assertions []*rainslib.AssertionSection
    shard *rainslib.ShardSection
    zone rainslib.ZoneSection
    sections []rainslib.MessageSectionWithSigForward
    objects []rainslib.Object
    object rainslib.Object
    objectTypes []rainslib.ObjectType
    objectType rainslib.ObjectType
    nameObject rainslib.NameObject
    signatures []rainslib.Signature
    signature rainslib.Signature
    shardRange []string
}

// any non-terminal which returns a value needs a type, which is
// really a field name in the above union struct
%type <zone> zone
%type <sections> zoneContent  
%type <shard> shard shardBody 
%type <shardRange> shardRange
%type <assertions> shardContent
%type <assertion> assertion assertionBody
%type <objects> object name ip4
%type <nameObject> nameBody   //ip6 redir deleg nameset 
//%type <str> cert serv regr regt infra extra next
%type <object> ip4Body
%type <objectTypes> oTypes 
%type <objectType> oType
%type <signatures> annotation annotationBody
%type <signature>  signature

// same for terminals
%token <str> ID
//section types
%token assertionType shardType zoneType
//object types
%token nameType ip4Type ip6Type redirType delegType namesetType certType
%token srvType regrType regtType infraType extraType nextType
//annotation types
%token sigType
//special
%token rangeBegin rangeEnd
%token lBracket rBracket lParenthesis rParenthesis

%% /* Grammer rules  */

top :   zone
    {
        fmt.Printf("\n%s\n", $1.String())
    }
    |   zone annotation
    {
        fmt.Printf("\n%s (%s)\n", $1.String(),$2)
    }

zone    : zoneType ID ID lBracket zoneContent rBracket
        {
            $$ = rainslib.ZoneSection{
                                        SubjectZone: $2, 
                                        Context: $3,
                                        Content: $5,    
                                    }
        }

zoneContent : /* empty */
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

shard   : shardBody
        | shardBody annotation
        {
            $$ = $1 //TODO CFE add annotation
        }

shardBody   : shardType ID ID shardRange lBracket shardContent rBracket
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

shardRange  : ID ID
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

shardContent : /* empty */
            {
                $$ = nil
            }
            | shardContent assertion
            {
                $$ = append($1,$2)
            }

assertion   : assertionBody
            | assertionBody annotation
            {
                $$ = $1 //TODO CFE add annotation
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

object  : name
        | ip4

name    : nameBody
        {
            $$ = []rainslib.Object{ rainslib.Object{
                                                    Type: rainslib.OTName,
                                                    Value: $1,
                                                    }}
        }
        | name nameBody
        {
            $$ = append($1,rainslib.Object{
                                            Type: rainslib.OTName,
                                            Value: $2,
                                            })
        }

nameBody : nameType ID lBracket oTypes rBracket
        {
            $$ = rainslib.NameObject{
                                        Name: $2,
                                        Types: $4,
            }
        }

oTypes  : oType
        {
            $$ = []rainslib.ObjectType{$1}
        }
        | oTypes oType
        {
            $$ = append($1,$2)
        }

oType   : nameType
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

ip4     : ip4Body
        {
            $$ = []rainslib.Object{$1}
        }
        | ip4 ip4Body
        {
            $$ = append($1,$2)
        }

ip4Body : ip4Type ID
        {
            $$ = rainslib.Object{
                                    Type: rainslib.OTIP4Addr,
                                    Value: $2,
            }
        }

annotation  : lParenthesis annotationBody rParenthesis
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

signature   : sigType ID ID ID ID ID
            {
                //TODO CFE complicated, lot of casting -> make tokens
                $$ = rainslib.Signature{}
            }
            | sigType ID ID ID ID ID ID
            {
                $$ = rainslib.Signature{}
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
	log.Error("syntax error:", "lineNr", l.lineNr+1, "wordNr", l.linePos,
	"token", l.lines[l.lineNr][l.linePos-1])
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