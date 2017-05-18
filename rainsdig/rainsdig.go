package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"rains/rainslib"
	"rains/utils/msgFramer"
	"rains/utils/parser"
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
		token := rainslib.GenerateToken()
		msg, err := generateMsg(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = sendQuery(msg, token, *serverAddr, *port)
		if err != nil {
			fmt.Println(err)
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
	message, err := parser.RainsMsgParser{}.ParseRainsMsg(msg)
	if err != nil {
		return []byte{}, fmt.Errorf("could not parse the query due to: %v", err)
	}

	return message, nil
}

func sendQuery(query []byte, token rainslib.Token, ipAddress string, port uint) error {
	conf := &tls.Config{
		//TODO CFE add this to cmd line options
		InsecureSkipVerify: true,
	}
	ipAddr := net.ParseIP(ipAddress)
	if ipAddr == nil {
		return errors.New("malformed IP address")
	}
	//TODO CFE reuse ConnInfo from rainsd -> add it to rainslib
	conn, err := tls.Dial("tcp", fmt.Sprintf("%v:%d", ipAddr, port), conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	done := make(chan rainslib.RainsMessage)
	parser := &parser.RainsMsgParser{}
	go func(conn net.Conn, parser rainslib.RainsMsgParser, token rainslib.Token) {
		framer := msgFramer.NewLineFramer{}
		framer.InitStream(conn)
		for framer.Deframe() {
			msg, err := parser.ParseByteSlice(framer.Data())
			if err != nil {
				log.Warn("Was not able to parse deframed message", "message", msg)
				continue
			}
			if msg.Token == token {
				done <- msg
				return
			}
			log.Debug("Token of sent query does not match the token of the received message", "queryToken", token, "recvToken", msg.Token)
		}
		done <- rainslib.RainsMessage{}
	}(conn, parser, token)
	_, err = conn.Write(append(query, []byte("\n")...))
	if err != nil {
		return err
	}
	result := <-done // wait for answer
	for _, section := range result.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection, *rainslib.ShardSection, *rainslib.ZoneSection:
			output, err := parser.RevParseSignedMsgSection(section.(rainslib.MessageSectionWithSig))
			if err != nil {
				log.Warn("Could not reverse parse section with signature", "error", err)
			}
			fmt.Println(output)
		case *rainslib.NotificationSection:
			//TODO implement a pretty printer
			fmt.Printf(":NO::TN:%v:NT:%d:ND:%s\n", section.Token, section.Type, section.Data)
		default:
			log.Warn("Unexpected section type", "Type", fmt.Sprintf("%T", section))
		}
	}
	return nil
}
