package main

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"
	"github.com/netsec-ethz/rains/utils/zoneFileParser"
)

//TODO add default values to description
var revLookup = flag.String("x", "", "Reverse lookup, addr is an IPv4 address in dotted-decimal notation, or a colon-delimited IPv6 address.")
var queryType = flag.Int("t", 3, "specifies the type for which dig issues a query.")
var name = flag.String("q", "", "sets the query's subjectName to this value.")
var port = flag.Uint("p", 5022, "is the port number that dig will send its queries to.")
var serverAddr = flag.String("s", "", `is the IP address of the name server to query.
		This can be an IPv4 address in dotted-decimal notation or an IPv6 address in colon-delimited notation.`)
var context = flag.String("c", ".", "context specifies the context for which dig issues a query.")
var expires = flag.Int64("exp", time.Now().Add(10*time.Second).Unix(), "expires sets the valid until value of the query.")
var filePath = flag.String("filePath", "", "specifies a file path where the query's response is appended to")
var insecureTLS = flag.Bool("insecureTLS", false, "when set it does not check the validity of the server's TLS certificate.")
var queryOptions qoptFlag

var msgParser rainslib.RainsMsgParser
var msgFramer rainslib.MsgFramer
var zfParser rainslib.ZoneFileParser

func init() {
	parserAndFramer := new(protoParser.ProtoParserAndFramer)
	msgParser = parserAndFramer
	msgFramer = parserAndFramer
	zfParser = zoneFileParser.Parser{}
	//TODO CFE this list should be generated from internal constants
	flag.Var(&queryOptions, "qopt", `specifies which query options are added to the query. Several query options are allowed. The sequence in which they are given determines the priority in descending order. Supported values are:
	1: Minimize end-to-end latency
	2: Minimize last-hop answer size (bandwidth)
	3: Minimize information leakage beyond first hop
	4: No information leakage beyond first hop: cached answers only
	5: Expired assertions are acceptable
	6: Enable query token tracing
	7: Disable verification delegation (client protocol only)
	8: Suppress proactive caching of future assertions
	e.g. to specify query options 4 and 2 with higher priority on option 4 write: -qopt=4 -qopt=2
	`)
}

//main parses the input flags, creates a query, send the query to the server defined in the input, waits for a response and writes the result to the command line.
func main() {
	flag.Parse()
	if *revLookup != "" {
		//TODO CFE implement reverse lookup
		fmt.Println("TODO CFE reverse lookup is not yet supported")
	} else {
		switch flag.NArg() {
		case 0:
			//all information present
		case 2:
			serverAddr = &flag.Args()[0]
			name = &flag.Args()[1]
		case 3:
			serverAddr = &flag.Args()[0]
			name = &flag.Args()[1]
			typeNo, err := strconv.Atoi(flag.Args()[2])
			if err != nil {
				fmt.Println("malformed type")
				os.Exit(1)
			}
			queryType = &typeNo
		default:
			fmt.Println("input parameters malformed")
		}

		tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", *serverAddr, *port))
		if err != nil {
			fmt.Printf("serverAddr malformed, error=%v\n", err)
			os.Exit(1)
		}
		connInfo := rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr}

		message := rainslib.NewQueryMessage(*name, *context, *expires,
			[]rainslib.ObjectType{rainslib.ObjectType(*queryType)}, queryOptions, rainslib.GenerateToken())
		msg, err := msgParser.Encode(message)
		if err != nil {
			fmt.Printf("could not encode the query, error=%s\n", err)
			os.Exit(1)
		}

		err = sendQuery(msg, message.Token, connInfo)
		if err != nil {
			fmt.Printf("could not frame and send the query, error=%s\n", err)
			os.Exit(1)
		}
	}
}

//sendQuery creates a connection with connInfo, frames msg and writes it to the connection.
//It then waits for the response which it then outputs to the command line and if specified additionally stores to a file.
func sendQuery(msg []byte, token rainslib.Token, connInfo rainslib.ConnInfo) error {
	conn, err := createConnection(connInfo)
	if err != nil {
		return err
	}
	defer conn.Close()
	msgFramer.InitStreams(conn, conn)
	done := make(chan rainslib.RainsMessage)
	go listen(conn, token, done)

	err = msgFramer.Frame(msg)
	if err != nil {
		return err
	}
	result := <-done // wait for answer
	for _, section := range result.Content {
		//FIXME CFE validate signature before displaying information, for that we need root publicKey, obtaining out of band?
		switch section := section.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection, *rainslib.QuerySection, *rainslib.NotificationSection,
			*rainslib.AddressAssertionSection, *rainslib.AddressQuerySection, *rainslib.AddressZoneSection:
			fmt.Println(zfParser.Encode(section))
		default:
			log.Warn("Unexpected section type", "Type", fmt.Sprintf("%T", section))
		}
	}
	return nil
}

//createConnection returns a newly created connection with connInfo or an error
func createConnection(connInfo rainslib.ConnInfo) (conn net.Conn, err error) {
	switch connInfo.Type {
	case rainslib.TCP:
		return tls.Dial(connInfo.TCPAddr.Network(), connInfo.String(), &tls.Config{InsecureSkipVerify: *insecureTLS})
	default:
		log.Warn("Unsupported Network address type.")
		return nil, errors.New("unsupported Network address type")
	}
}

//listen receives incoming messages. If the message's token matches the query's token, it sends the message back over the channel otherwise it discards the message.
func listen(conn net.Conn, token rainslib.Token, done chan<- rainslib.RainsMessage) {
	for msgFramer.DeFrame() {
		tok, err := msgParser.Token(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to extract the token", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			continue
		}
		msg, err := msgParser.Decode(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to decode received message", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			if tok == token {
				done <- msg
				return
			}
			continue
		}
		if tok == token {
			done <- msg
			return
		} else if n, ok := msg.Content[0].(*rainslib.NotificationSection); ok && n.Token == token {
			done <- msg
			return
		}
		log.Debug("Token of sent query does not match the token of the received message", "queryToken", token, "recvToken", msg.Token)
	}
	done <- rainslib.RainsMessage{}
}

//qoptFlag defines the query options flag. It allows a user to specify multiple query options and their priority (by input sequence)
type qoptFlag []rainslib.QueryOption

func (i *qoptFlag) String() string {
	list := []string{}
	for _, opt := range *i {
		list = append(list, strconv.Itoa(int(opt)))
	}
	return fmt.Sprintf("[%s]", strings.Join(list, " "))
}

//Set transforms command line input of a query option to its internal representation
func (i *qoptFlag) Set(value string) error {
	switch value {
	case "1":
		*i = append(*i, rainslib.QOMinE2ELatency)
	case "2":
		*i = append(*i, rainslib.QOMinLastHopAnswerSize)
	case "3":
		*i = append(*i, rainslib.QOMinInfoLeakage)
	case "4":
		*i = append(*i, rainslib.QOCachedAnswersOnly)
	case "5":
		*i = append(*i, rainslib.QOExpiredAssertionsOk)
	case "6":
		*i = append(*i, rainslib.QOTokenTracing)
	case "7":
		*i = append(*i, rainslib.QONoVerificationDelegation)
	case "8":
		*i = append(*i, rainslib.QONoProactiveCaching)
	default:
		return fmt.Errorf("There is no query option for value: %s", value)

	}
	return nil
}
