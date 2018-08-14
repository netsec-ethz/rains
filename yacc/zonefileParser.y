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
)

var regs = make([]int, 26)
var base int

%}

// fields inside this union end up as the fields in a structure known
// as ${PREFIX}SymType, of which a reference is passed to the lexer.
%union{
    str string
}

// any non-terminal which returns a value needs a type, which is
// really a field name in the above union struct
%type <str> assertion zone object annotation

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
%token '[' ']' '(' ')'


%left '|'
%left '&'
%left '+'  '-'
%left '*'  '/'  '%'
%left UMINUS      /*  supplies  precedence  for  unary  minus  */

%%

top :   zone
    {
        fmt.Printf("%s\n", $1)
    }
    |   zone '(' annotation ')'
    {
        fmt.Printf("%s\n", $1)
    }
	;

zone : zoneType ID ID
    {
        $$ = $2
    }
     ;

annotation : sigType ID stat
    {
        $$ = $2
    }
     ;

stat	:   assertionType assertion
        {
            fmt.Printf( "%s\n", "assertion");
        }
	;

assertion : ID  object
        {
            $$ = $1
            fmt.Printf( "%s\n", $1);
        }
    ;

object : ip4Type ID
        {
            $$ = $2
            fmt.Printf( "%s\n", $2);
        }
    ;

%%      /*  start  of  programs  */

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
    //read data
    line := l.lines[l.lineNr]
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
    case "<" :
        return rangeBegin
    case ">" :
        return rangeEnd
	default :
        lval.str = word
        return ID
	}
}

// The parser calls this method on a parse error.
func (l *ZFPLex) Error(s string) {
	log.Error("syntax error:", "lineNr", l.lineNr, "linePosition", l.linePos-1,
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
        if len(words) != 0 {
            lines = append(lines, words)
        }
    }
    return lines
}