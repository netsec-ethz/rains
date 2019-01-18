package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	flag "github.com/spf13/pflag"
)

//Options
var qType = flag.StringP("type", "t", "ip6", `specifies the type for which rdig issues a query. Allowed 
types are: name, ip6, ip4, redir, deleg, nameset, cert, srv, regr, regt, infra, extra, next. If no 
type argument is provided, the type is set to ip6`)
var port = flag.UintP("port", "p", 55553,
	"is the port number that rdig will send its queries to. The default port is 55553.")
var keyPhase = flag.IntP("keyphase", "k", 0,
	"is the key phase for which a delegation is requested. The default key phase is 0.")
var context = flag.StringP("context", "c", ".",
	"specifies the context for which rdig issues a query. The default context is the global context '.'.")
var expires = flag.Int64P("expires", "e", time.Now().Add(time.Second).Unix(),
	"expires sets the valid until value of the query. A query expires after one second per default.")
var insecureTLS = flag.BoolP("insecureTLS", "i", false,
	"when set it does not check the validity of the server's TLS certificate. The certificate is checked by default.")
var nonce = flag.StringP("nonce", "n", "",
	"specifies a nonce to be used in the query instead of using a randomly generated one.")

//Query Options
var minEE = flag.BoolP("minEE", "1", false, "Minimize end-to-end latency")
var minAS = flag.BoolP("minAS", "2", false, "Minimize last-hop answer size (bandwidth)")
var minIL = flag.BoolP("minIL", "3", false, "Minimize information leakage beyond first hop")
var noIL = flag.BoolP("noIL", "4", false, "No information leakage beyond first hop: cached answers only")
var exp = flag.BoolP("exp", "5", false, "Expired assertions are acceptable")
var tracing = flag.BoolP("tracing", "6", false, "Enable query token tracing")
var noVD = flag.BoolP("noVD", "7", false, "Disable verification delegation (client protocol only)")
var noCaching = flag.BoolP("noCaching", "8", false, "Suppress proactive caching of future assertions")
var maxAF = flag.BoolP("maxAF", "9", false, "Maximize answer freshness")

func init() {
	flag.CommandLine.SortFlags = false
	flag.Lookup("insecureTLS").NoOptDefVal = "true"
	flag.Lookup("minEE").NoOptDefVal = "true"
	flag.Lookup("minAS").NoOptDefVal = "true"
	flag.Lookup("minIL").NoOptDefVal = "true"
	flag.Lookup("noIL").NoOptDefVal = "true"
	flag.Lookup("exp").NoOptDefVal = "true"
	flag.Lookup("tracing").NoOptDefVal = "true"
	flag.Lookup("noVD").NoOptDefVal = "true"
	flag.Lookup("noCaching").NoOptDefVal = "true"
	flag.Lookup("maxAF").NoOptDefVal = "true"
}

func main() {
	flag.Parse()
	var name, server string
	switch flag.NArg() {
	case 0:
		log.Fatal("Error: no domain name specified.")
	case 1:
		name = flag.Arg(0)
		if strings.HasPrefix(name, "@") {
			log.Fatal("Error: no domain name specified.")
		}
	case 2:
		server = flag.Arg(0)
		if !strings.HasPrefix(server, "@") {
			log.Fatal("Error: server name or addr does not start with an @")
		}
		name = flag.Arg(1)
	case 3:
		server = flag.Arg(0)
		if !strings.HasPrefix(server, "@") {
			log.Fatal("Error: server name or addr does not start with an @")
		}
		name = flag.Arg(1)
		t := flag.Arg(2)
		qType = &t
	default:
		fmt.Println("input parameters malformed")
	}
	if _, err := net.ResolveIPAddr("", server[1:]); err != nil {
		//FIXME
		log.Fatal("Error: default server not yet implemented. Please specify a server addr")
	}

	tcpAddr, err := net.ResolveTCPAddr("", fmt.Sprintf("%s:%d", server[1:], *port))
	if err != nil {
		log.Fatalf("Error: serverAddr or port malformed: %v", err)
	}

	qTypes, err := object.ParseTypes(*qType)
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}

	tok := token.New()
	if flag.Lookup("nonce").Changed {
		for i := 0; i < len(tok); i++ {
			if i < len(*nonce) {
				tok[i] = (*nonce)[i]
			} else {
				tok[i] = 0x0
			}
		}
	}

	msg := util.NewQueryMessage(name, *context, *expires, qTypes, parseAllQueryOptions(), tok)

	answerMsg, err := util.SendQuery(msg, tcpAddr, time.Second)
	if err != nil {
		log.Fatalf("was not able to send query: %v", err)
	}
	fmt.Println(zonefile.IO{}.Encode(answerMsg.Content))
}

func parseAllQueryOptions() []query.Option {
	qOptions := []query.Option{}
	addOption := func(f *flag.Flag) {
		if opt, ok := parseQueryOption(f.Shorthand); ok {
			qOptions = append(qOptions, opt)
		}
	}
	flag.Visit(addOption)
	return qOptions
}

func parseQueryOption(name string) (query.Option, bool) {
	switch name {
	case "1":
		return query.QOMinE2ELatency, true
	case "2":
		return query.QOMinLastHopAnswerSize, true
	case "3":
		return query.QOMinInfoLeakage, true
	case "4":
		return query.QOCachedAnswersOnly, true
	case "5":
		return query.QOExpiredAssertionsOk, true
	case "6":
		return query.QOTokenTracing, true
	case "7":
		return query.QONoVerificationDelegation, true
	case "8":
		return query.QONoProactiveCaching, true
	case "9":
		return query.QOMaxFreshness, true
	default:
		return query.Option(-1), false
	}
}
