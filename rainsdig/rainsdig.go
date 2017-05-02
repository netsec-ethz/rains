package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/parser"
)

//TODO add default values to description
var revLookup = flag.String("x", "", "Reverse lookup, addr is an IPv4 address in dotted-decimal notation, or a colon-delimited IPv6 address")
var queryType = flag.Int("t", 3, "type specifies the type for which dig issues a query")
var name = flag.String("q", "", "sets the query's subjectName to this value")
var port = flag.Uint("p", 5022, "port is the port number that dig will send its queries to")
var serverAddr = flag.String("s", "", `is the IP address of the name server to query. 
		This can be an IPv4 address in dotted-decimal notation or an IPv6 address in colon-delimited notation.`)
var context = flag.String("c", ".", "context specifies the context for which dig issues a query")
var expires = flag.Int("exp", int(time.Now().Add(10*time.Second).Unix()), "expires sets the valid until value of the query")

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
		msg, err := generateMsg()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = sendQuery(msg, *serverAddr, *port)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}

func generateMsg() ([]byte, error) {
	token := rainslib.GenerateToken()
	section := rainslib.QuerySection{
		Context: *context,
		Expires: *expires,
		Type:    rainslib.ObjectType(*queryType),
		Token:   token,
		Name:    *name,
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

func sendQuery(query []byte, ipAddress string, port uint) error {
	conf := &tls.Config{
		//TODO CFE add this to cmd line options
		InsecureSkipVerify: true,
	}
	ipAddr := net.ParseIP(ipAddress)
	if ipAddr == nil {
		return errors.New("malformed IP address")
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%v:%d", ipAddr, port), conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		//TODO CFE format answer and stop after received one
		io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()
	_, err = conn.Write(append(query, []byte("\n")...))
	if err != nil {
		return err
	}
	<-done // wait for answer
	return nil
}
