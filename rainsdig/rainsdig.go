package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"rains/rainslib"
	"rains/utils/protoParser"
	"rains/utils/zoneFileParser"
	"strconv"
	"time"

	log "github.com/inconshreveable/log15"
)

//TODO add default values to description
var revLookup = flag.String("x", "", "Reverse lookup, addr is an IPv4 address in dotted-decimal notation, or a colon-delimited IPv6 address")
var queryType = flag.Int("t", 3, "type specifies the type for which dig issues a query")
var name = flag.String("q", "", "sets the query's subjectName to this value")
var port = flag.Uint("p", 5022, "port is the port number that dig will send its queries to")
var serverAddr = flag.String("s", "", `is the IP address of the name server to query. 
		This can be an IPv4 address in dotted-decimal notation or an IPv6 address in colon-delimited notation.`)
var context = flag.String("c", ".", "context specifies the context for which dig issues a query")
var expires = flag.Int64("exp", time.Now().Add(10*time.Second).Unix(), "expires sets the valid until value of the query")

//TODO CFE enable to set multiple query options
var queryOption = flag.Int("qopt", 0, "queryOption specifies performance/privacy tradeoffs")

var msgParser rainslib.RainsMsgParser
var msgFramer rainslib.MsgFramer
var zfParser rainslib.ZoneFileParser

func init() {
	parserAndFramer := new(protoParser.ProtoParserAndFramer)
	msgParser = parserAndFramer
	msgFramer = parserAndFramer
	zfParser = zoneFileParser.Parser{}
}

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
		}
		connInfo := rainslib.ConnInfo{Type: rainslib.TCP, TCPAddr: tcpAddr}

		token := rainslib.GenerateToken()
		msg, err := generateMsg(token)
		if err != nil {
			fmt.Printf("could not encode the query, error=%s\n", err)
			os.Exit(1)
		}

		err = sendQuery(msg, token, connInfo)
		if err != nil {
			fmt.Printf("could not frame and send the query, error=%s\n", err)
			os.Exit(1)
		}
	}
}

func generateMsg(token rainslib.Token) ([]byte, error) {
	section := rainslib.QuerySection{
		Context: *context,
		Expires: *expires,
		Type:    rainslib.ObjectType(*queryType),
		Token:   token,
		Name:    *name,
	}
	if *queryOption > 0 && *queryOption < 6 {
		section.Options = []rainslib.QueryOption{rainslib.QueryOption(*queryOption)}
	}
	msg := rainslib.RainsMessage{
		Token:   token,
		Content: []rainslib.MessageSection{&section},
	}
	return msgParser.Encode(msg)
}

func sendQuery(query []byte, token rainslib.Token, connInfo rainslib.ConnInfo) error {
	conf := &tls.Config{
		//TODO CFE add this to cmd line options
		InsecureSkipVerify: true,
	}
	var conn net.Conn
	var err error
	switch connInfo.Type {
	case rainslib.TCP:
		conn, err = tls.Dial(connInfo.TCPAddr.Network(), connInfo.String(), conf)
		if err != nil {
			return err
		}
		defer conn.Close()
	default:
		log.Warn("Unsupported Network address type.")
	}

	msgFramer.InitStreams(conn, conn)
	done := make(chan rainslib.RainsMessage)
	go listen(conn, token, done)

	err = msgFramer.Frame(query)
	if err != nil {
		return err
	}
	result := <-done // wait for answer
	for _, section := range result.Content {
		//FIXME CFE validate signature before displaying information?
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

//listen receives incoming messages. If the message's token matches the query's token, it sends the message back over the channel otherwise it discards the message.
func listen(conn net.Conn, token rainslib.Token, done chan<- rainslib.RainsMessage) {
	for msgFramer.DeFrame() {
		msg, err := msgParser.Decode(msgFramer.Data())
		if err != nil {
			log.Warn("Was not able to decode received message", "message", hex.EncodeToString(msgFramer.Data()), "error", err)
			continue
		}
		if msg.Token == token {
			done <- msg
			return
		}
		log.Debug("Token of sent query does not match the token of the received message", "queryToken", token, "recvToken", msg.Token)
	}
	done <- rainslib.RainsMessage{}
}
