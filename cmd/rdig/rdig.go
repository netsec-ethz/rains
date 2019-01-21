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
var qType = flag.StringP("type", "t", "ip6", "specifies the type for which rdig issues a query. "+
	"Allowed types are: name, ip6, ip4, redir, deleg, nameset, cert, srv, regr, regt, infra, extra, next.")
var port = flag.UintP("port", "p", 55553,
	"is the port number that rdig will send its queries to.")
var keyPhase = flag.IntP("keyphase", "k", 0,
	"is the key phase for which a delegation is requested. (default 0)")
var context = flag.StringP("context", "c", ".",
	"specifies the context for which rdig issues a query.")
var expires = flag.Int64P("expires", "e", time.Now().Add(time.Second).Unix(),
	"expires sets the valid until timestamp of the query in unix seconds since 1970. (default current timestamp + 1 second)")
var insecureTLS = flag.BoolP("insecureTLS", "i", false,
	"when set it does not check the validity of the server's TLS certificate. (default false)")
var nonce = flag.StringP("nonce", "n", "",
	"specifies a nonce to be used in the query instead of using a randomly generated one.")

//Query Options
var minEE = flag.BoolP("minEE", "1", false, "Query option: Minimize end-to-end latency")
var minAS = flag.BoolP("minAS", "2", false, "Query option: Minimize last-hop answer size (bandwidth)")
var minIL = flag.BoolP("minIL", "3", false, "Query option: Minimize information leakage beyond first hop")
var noIL = flag.BoolP("noIL", "4", false, "Query option: No information leakage beyond first hop: cached answers only")
var exp = flag.BoolP("exp", "5", false, "Query option: Expired assertions are acceptable")
var tracing = flag.BoolP("tracing", "6", false, "Query option: Enable query token tracing")
var noVD = flag.BoolP("noVD", "7", false, "Query option: Disable verification delegation (client protocol only)")
var noCaching = flag.BoolP("noCaching", "8", false, "Query option: Suppress proactive caching of future assertions")
var maxAF = flag.BoolP("maxAF", "9", false, "Query option: Maximize answer freshness")

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
	case 1, 2, 3:
		if !handleArgs(&server, &name, qType, flag.Args()...) {
			log.Fatal("Error: no domain name specified.")
		}
	default:
		fmt.Println("Error: too many arguments")
	}
	log.Fatalf("%s %s %s", server, name, *qType)
	if _, err := net.ResolveIPAddr("", server); err != nil {
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

//handleArgs stores the cmd line argument with prefix '@' in srvAddr and additional arguments in
//name and qType. It returns false when no name was specified
func handleArgs(srvAddr, name, qType *string, args ...string) bool {
	nameSet := false
	for _, a := range args {
		if strings.HasPrefix(a, "@") {
			*srvAddr = a[1:]
		} else {
			if nameSet {
				*qType = a
			} else {
				*name = a
				nameSet = true
			}
		}
	}
	return nameSet
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
