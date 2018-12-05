// Package libresolve implements a recursive and stub resolver for RAINS.
package libresolve

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/generate"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

var (
	defaultTimeout      = 10 * time.Second
	defaultFailFast     = true
	defaultInsecureTLS  = false
	defaultQueryTimeout = time.Duration(1000) //in milliseconds
)

type ResolutionMode int

const (
	Recursive ResolutionMode = iota
	Forward
)

// Resolver provides methods to resolve names in RAINS.
type Resolver struct {
	RootNameServers []connection.Info
	Forwarders      []connection.Info
	Mode            ResolutionMode
	InsecureTLS     bool
	DialTimeout     time.Duration
	FailFast        bool
	Delegations     map[string]*section.Assertion
	Connections     map[connection.Info]net.Conn
}

//New creates a resolver with the given parameters and default settings
func New(rootNS, forwarders []connection.Info, mode ResolutionMode, addr connection.Info) *Resolver {
	return &Resolver{
		RootNameServers: rootNS,
		Forwarders:      forwarders,
		Mode:            mode,
		InsecureTLS:     defaultInsecureTLS,
		DialTimeout:     defaultTimeout,
		FailFast:        defaultFailFast,
		Delegations:     make(map[string]*section.Assertion),
		Connections:     make(map[connection.Info]net.Conn),
	}
}

//ClientLookup forwards the query to the specified forwarders or performs a recursive lookup starting at
//the specified root servers. It returns the received information.
func (r *Resolver) ClientLookup(query *query.Name) (*message.Message, error) {
	switch r.Mode {
	case Recursive:
		return r.recursiveResolve(query)
	case Forward:
		return r.forwardQuery(query)
	default:
		return nil, fmt.Errorf("Unsupported resolution mode: %v", r.Mode)
	}
}

//ServerLookup forwards the query to the specified forwarders or performs a recursive lookup
//starting at the specified root servers. It sends the received information to conInfo.
func (r *Resolver) ServerLookup(query *query.Name, connInfo connection.Info) {
	var msg message.Message
	switch r.Mode {
	case Recursive:
		msg, _ := r.recursiveResolve(query)
	case Forward:
		msg, _ := r.forwardQuery(query)
	default:
		log.Error("Unsupported resolution mode", "mode", r.Mode)
	}
	if conn, ok := r.Connections[connInfo]; ok {
		writer := cbor.NewWriter(conn)
		if err := writer.Marshal(&msg); err != nil {
			r.createConnAndWrite(connInfo, msg) //Connection has been closed in the mean time
		}
	} else {
		r.createConnAndWrite(connInfo, msg)
	}
}

func (r *Resolver) createConnAndWrite(connInfo connection.Info, msg message.Message) {
	conn, err := connection.CreateConnection(connInfo)
	r.Connections[connInfo] = conn
	go r.answerDelegQueries(conn, connInfo)
	writer := cbor.NewWriter(conn)
	if err := writer.Marshal(&msg); err != nil {
		log.Error("failed to marshal message", err)
		delete(r.Connections, connInfo)
	}
}

//answerDelegQueries answers delegation queries on conn from its cache. The cache is populated
//through delegations received in a recursive lookup.
func (r *Resolver) answerDelegQueries(conn net.Conn, connInfo connection.Info) {
	var msg message.Message
	reader := cbor.NewReader(conn)
	writer := cbor.NewWriter(conn)
	for {
		if err := reader.Unmarshal(&msg); err != nil {
			if err.Error() == "failed to read tag: EOF" {
				log.Info("Connection has been closed", "conn", connInfo)
			} else {
				log.Warn(fmt.Sprintf("failed to read from client: %v", err))
			}
			delete(r.Connections, connInfo)
			break
		}
		answer := r.getDelegations(msg)
		msg = message.Message{Token: msg.Token, Content: answer}
		if err := writer.Marshal(&msg); err != nil {
			log.Error("failed to marshal message", err)
			delete(r.Connections, connInfo)
			break
		}
	}
}

//getDelegations returns all cached delegations answering a query in msg.
func (r *Resolver) getDelegations(msg message.Message) []section.Section {
	answer := []section.Section{}
	for _, s := range msg.Content {
		if q, ok := s.(*query.Name); ok {
			for _, t := range q.Types {
				if t == object.OTDelegation {
					if a, ok := r.Delegations[q.Name]; ok {
						answer = append(answer, a)
					} else {
						log.Warn("requested delegation is not cached. This should never happen")
					}
					break
				}
			}
		}
	}
	return answer
}

func (r *Resolver) forwardQuery(q *query.Name) (*message.Message, error) {
	if len(r.Forwarders) == 0 {
		return nil, errors.New("forwarders must be specified to use this mode")
	}
	for _, forwarder := range r.Forwarders {
		msg := message.Message{Token: token.New(), Content: []section.Section{q}}
		answer, err := util.SendQuery(msg, forwarder, r.DialTimeout*time.Millisecond)
		if err == nil {
			return &answer, nil
		}
	}
	return nil, fmt.Errorf("could not connect to any of the specified resolver: %v", r.Forwarders)
}

// recursiveResolve starts at the root and follows delegations until it receives an answer.
func (r *Resolver) recursiveResolve(q *query.Name) (*message.Message, error) {
	for _, root := range r.RootNameServers {
		log.Debug("connecting to root server", "serverAddr", root, "query", q)
		msg := message.Message{Token: token.New(), Content: []section.Section{q}}
		connInfo := root
		for {
			answer, err := util.SendQuery(msg, connInfo, r.DialTimeout*time.Millisecond)
			if err != nil || len(answer.Content) == 0 {
				continue
			}
			//Check if answer is final or a delegation
			types := make(map[object.Type]bool)
			redirMap := make(map[string]string)
			delegMap := make(map[string]string)
			srvMap := make(map[string]object.ServiceInfo)
			ipMap := make(map[string]string)
			for _, t := range q.Types {
				types[t] = true
			}
			isRedir := false
			finalAnswer := false
			for _, sec := range answer.Content {
				switch s := sec.(type) {
				case *section.Assertion:
					handleAssertion()
				case *section.Shard:
					handleShard()
				case *section.Zone:
					handleZone()
				}
			}
			if finalAnswer {
				//send back
			} else if isRedir {
				// If we are here, there is some recursion required or there is no answer.
				// Firstly we check if there is some redirection for a suffix we are interested in.
				redirTarget := ""
				for key, value := range redirectMap {
					if strings.HasSuffix(name, key) {
						redirTarget = value
					}
				}
				if redirTarget == "" {
					return nil, fmt.Errorf("failed to find result or redirection, response was: %v", resp)
				}
				// Follow redir until we encounter a srv.
				seen := make(map[string]bool)
				for {
					if _, ok := seen[redirTarget]; ok {
						return nil, fmt.Errorf("redirect loop detected, target %q, response: %v", redirTarget, resp)
					}
					seen[redirTarget] = true
					if next, ok := redirectMap[redirTarget]; ok {
						redirTarget = next
					} else {
						break
					}
				}
				// There should now be a mapping between the next redirTarget and a serviceinfo object.
				if srvInfo, ok := srvMap[redirTarget]; ok {
					// srvInfo should contain a name
					if concreteTarget, ok := concreteMap[srvInfo.Name]; ok {
						latestResolver = fmt.Sprintf("%s:%d", concreteTarget, srvInfo.Port)
					} else {
						return nil, fmt.Errorf("serviceInfo target could not be found in response, target: %q, resp: %v", srvInfo.Name, resp)
					}
				} else {
					return nil, fmt.Errorf("recieved incomplete response, missing serviceInfo for target FQDN %q, resp: %v", redirTarget, resp)
				}
				//TODO warn, if no delegation assertion was received. Must request it so we can
				//answer caching resolver or client.
			} else {
				log.Warn("received unexpected answer to query. Recursive lookup cannot be continued")
				break
			}

		}

	}
}

func handleAssertion() {
	//TODO
}

func handleShard() {
	//TODO
}

func handleZone() {
	//TODO
}

func forwardQuery(msg message.Message, input *connection.Channel, forward func(connection.Message),
	addr string, continent, tld int, delay *generate.Delay) token.Token {
	msg.Token = token.New()
	encoding := new(bytes.Buffer)
	err := msg.MarshalCBOR(borat.NewCBORWriter(encoding))
	panicOnError(err)
	//TODO CFE instead of adding all the delay when sending, add half of it when it is received
	log.Info("RTT to naming server", "Delay", delay.Calc(continent, tld, addr))
	time.Sleep(delay.Calc(continent, tld, addr))
	forward(connection.Message{Msg: encoding.Bytes(), Sender: input})
	log.Info("RR sent message to naming server", "namingServer", addr, "msg", msg)
	return msg.Token
}

func NameToLabels(name string) ([]string, error) {
	if !strings.HasSuffix(name, ".") {
		return nil, fmt.Errorf("domain name must end with root qualifier '.', got %s", name)
	}
	parts := strings.Split(name, ".")
	// Last element is empty because of root dot, so discard it.
	return parts[:len(parts)-1], nil
}

func (r *Resolver) nameToQuery(name, context string, expTime int64, opts []query.Option) message.Message {
	types := []object.Type{object.OTIP4Addr, object.OTIP6Addr, object.OTDelegation, object.OTServiceInfo, object.OTRedirection}
	return util.NewQueryMessage(name, context, expTime, types, opts, token.New())
}

// listen waits for one message and passes it back on the provided channel, or an error on the error channel.
func listen(conn net.Conn, tok token.Token, done chan<- *message.Message, ec chan<- error) {
	reader := cbor.NewReader(conn)
	var msg message.Message
	if err := reader.Unmarshal(&msg); err != nil {
		ec <- fmt.Errorf("failed to unmarshal response: %v", err)
		return
	}
	if msg.Token != tok {
		ec <- fmt.Errorf("token response mismatch: got %v, want %v", msg.Token, tok)
		return
	}
	done <- &msg
}
