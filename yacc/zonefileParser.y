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
    assertion rainslib.AssertionSection
    shard rainslib.ShardSection
    zone rainslib.ZoneSection
}

// any non-terminal which returns a value needs a type, which is
// really a field name in the above union struct
%type <zone> zone
%type <str> zoneContent 
%type <str> shard shardBody shardRange shardContent
%type <str> assertion assertionBody
%type <str> object name ip4 //ip6 redir deleg nameset 
//%type <str> cert serv regr regt infra extra next
%type <str> nameBody ip4Body
%type <str> oTypes oType

%type <str> annotation annotationBody signature

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
        fmt.Printf("\n%s\n", $1)
    }
    |   zone annotation
    {
        fmt.Printf("\n%s (%s)\n", $1.String(),$2)
    }

zone    : zoneType ID ID lBracket zoneContent rBracket
        {
            $$ = rainslib.ZoneSection{SubjectZone: $2, Context: $3}
        }

zoneContent : /* empty */
            {
                $$ = ""
            }
            | zoneContent assertion
            {
                $$ = fmt.Sprintf("%s %s", $1, $2)
            }
            | zoneContent shard
            {
                $$ = fmt.Sprintf("%s %s", $1, $2)
            }

shard   : shardBody
        | shardBody annotation
        {
            fmt.Printf("%s (%s)", $1,$2)
        }

shardBody   : shardType ID ID shardRange lBracket shardContent rBracket
            {
                $$ = fmt.Sprintf("S %s %s %s", $2, $3, $4)
            }
            | shardType shardRange lBracket shardContent rBracket
            {
                $$ = fmt.Sprintf("S %s ", $2)
            }

shardRange  : ID ID
            {
                $$ = fmt.Sprintf("%s %s", $1, $2)
            }
            | rangeBegin ID
            {
                $$ = fmt.Sprintf("< %s", $2)
            }
            | ID rangeEnd
            {
                $$ = fmt.Sprintf("%s >", $1)
            }
            | rangeBegin rangeEnd
            {
                $$ = fmt.Sprint("< >")
            }

shardContent : /* empty */
            {
                $$ = ""
            }
            | shardContent assertion
            {
                $$ = fmt.Sprintf("%s %s", $1, $2)
            }

assertion   : assertionBody
            | assertionBody annotation
            {
                fmt.Printf("%s (%s)", $1,$2)
            }
    
assertionBody   : assertionType ID lBracket object rBracket
                {
                    $$ = fmt.Sprintf("A %s [ %s ]", $2, $4)
                }
                | assertionType ID ID ID lBracket object rBracket
                {
                    $$ = fmt.Sprintf("A %s %s %s [ %s ] (%s)", $2, $4, $6)
                }

object  : name
        | ip4

name    : nameBody
        | name nameBody
        {
            $$ = fmt.Sprintf("%s %s", $1, $2)
        }

nameBody : nameType ID lBracket oTypes rBracket
        {
            $$ = fmt.Sprintf("name %s [%s]", $2, $4)
        }

oTypes  : oType
        | oTypes oType
        {
            $$ = fmt.Sprintf("%s %s", $1, $2)
        }

oType   : nameType
        {
            $$ = "a Type"
        }
        | ip4Type
        {
            $$ = "a Type"
        }
        | ip6Type
        {
            $$ = "a Type"
        }
        | redirType
        {
            $$ = "a Type"
        }
        | delegType
        {
            $$ = "a Type"
        }
        | namesetType
        {
            $$ = "a Type"
        }
        | certType
        {
            $$ = "a Type"
        }
        | srvType
        {
            $$ = "a Type"
        }
        | regrType
        {
            $$ = "a Type"
        }
        | regtType
        {
            $$ = "a Type"
        }
        | infraType
        {
            $$ = "a Type"
        }
        | extraType
        {
            $$ = "a Type"
        }
        | nextType
        {
            $$ = "a Type"
        }

ip4     : ip4Body
        | ip4 ip4Body
        {
            $$ = fmt.Sprintf("%s %s", $1, $2)
        }

ip4Body : ip4Type ID
        {
            $$ = fmt.Sprintf("ip4 %s", $2)
        }

annotation  : lParenthesis annotationBody rParenthesis
            {
                $$ = $2
            }

annotationBody  : signature
                | annotationBody signature

signature   : sigType ID ID ID ID ID
            {
                $$ = fmt.Sprintf("sigMeta %s %s %s %s %s", $2, $3, $4, $5, $6)
            }
            | sigType ID ID ID ID ID ID
            {
                $$ = fmt.Sprintf("%s %s %s %s %s %s", $2, $3, $4, $5,
                $6, $7)
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