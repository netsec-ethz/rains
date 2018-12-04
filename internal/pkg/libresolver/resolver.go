// Package libresolve implements a recursive and stub resolver for RAINS.
package libresolve

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/connection"

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
func New(rootNS, forwarders []connection.Info, mode ResolutionMode) *Resolver {
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
	writer := cbor.NewWriter(conn)
	if err := writer.Marshal(&msg); err != nil {
		log.Error("failed to marshal message", err)
	}
	r.Connections[connInfo] = conn
	//FIXME implement listener, to respond to server when he requests delegations
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
			//TODO maybe use a better heuristic
			redir := false
			for _, sec := range answer.Content {
				if a, ok := sec.(*section.Assertion); ok {
					for _, o := range a.Content {
						if o.Type == object.OTRedirection {
							redir = true
						}
					}
				}
			}
		}
		d := &net.Dialer{
			Timeout: r.DialTimeout,
		}
		conn, err := tls.DialWithDialer(d, "tcp", latestResolver, &tls.Config{InsecureSkipVerify: r.InsecureTLS})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to resolver: %v", err)
		}
		defer conn.Close()
		writer := cbor.NewWriter(conn)
		q := r.nameToQuery(name, context, time.Now().Add(15*time.Second).Unix(), []query.Option{})
		if err := writer.Marshal(&q); err != nil {
			return nil, fmt.Errorf("failed to marshal query to server: %v", err)
		}
		done := make(chan *message.Message)
		ec := make(chan error)
		go listen(conn, q.Token, done, ec)
		select {
		case msg := <-done:
			resp = msg
		case err := <-ec:
			return nil, err
		}
		if len(resp.Content) == 0 {
			return nil, errors.New("got empty response")
		}
		// The response can either be a redirection chain or a response.
		redirectMap := make(map[string]string)
		srvMap := make(map[string]object.ServiceInfo)
		concreteMap := make(map[string]string)
		for _, sec := range resp.Content {
			switch sec.(type) {
			case *section.Zone:
				// If we were given a whole zone it's because we asked for it or it's non-existance proof.
				return resp, nil
			case *section.Assertion:
				as := sec.(*section.Assertion)
				sz := mergeSubjectZone(as.SubjectName, as.SubjectZone)
				if sz == name {
					return resp, nil
				}
				for _, obj := range as.Content {
					switch obj.Type {
					case object.OTRedirection:
						redirectMap[sz] = obj.Value.(string)
					case object.OTServiceInfo:
						si := obj.Value.(object.ServiceInfo)
						srvMap[sz] = si
					case object.OTIP4Addr:
						concreteMap[sz] = obj.Value.(string)
					case object.OTIP6Addr:
						concreteMap[sz] = fmt.Sprintf("[%s]", obj.Value.(string))
					}
				}
			case *section.Shard:
				return resp, nil
			default:
				return nil, fmt.Errorf("got unknown type: %T", sec)
			}
		}
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
	}
}

/*func (s *Server) Start() {
	log.Info("Starting recursive resolver", "ID", s.input.RemoteAddr().String())
	for {
		msg := <-s.input.RemoteChan
		m := &message.Message{}
		reader := cbor.NewReader(bytes.NewBuffer(msg.Msg))
		if err := reader.Unmarshal(m); err != nil {
			log.Warn(fmt.Sprintf("failed to unmarshal msg recv over channel: %v", err))
			continue
		}
		//if "-"+msg.Sender.RemoteAddr().String() == s.input.RemoteAddr().String() { FIXME CFE
		//RemoteAddr is not correctly returned by naming server. Why?
		if oldMsg, ok := s.newTokenToMsg[m.Token]; !ok {
			//New query from the caching resolver
			log.Info("RR received message from caching resolver", "resolver", msg.Sender.RemoteAddr().String(), "msg", m)
			q := m.Query()
			if q.Types[0] == object.OTDelegation {
				if a, ok := s.delegations[q.Name]; ok {
					m.Content = []section.Section{a}
					returnToCachingResolver(m.Token, *m, s.input, s.cachingResolver)
					continue
				}
			}
			newToken := forwardQuery(*m, s.input, s.ipToChan[s.rootIPAddr], s.rootIPAddr, s.continent, s.tld, s.delay)
			s.newTokenToMsg[newToken] = m
		} else {
			//New answer from a recursive lookup
			//FIXME does not work with self reference in subjectName (@)
			log.Info("RR received message from a naming server", "namingServer", msg.Sender.RemoteAddr().String(), "msg", m)
			//oldMsg := s.newTokenToMsg[m.Token] //FIXME CFE see above
			switch sec := m.Content[0].(type) {
			case *section.Assertion:
				if sec.Content[0].Type == object.OTDelegation {
					s.delegations[sec.FQDN()] = sec
				}
				if oldMsg.Query().Name == sec.FQDN() {
					returnToCachingResolver(oldMsg.Token, *m, s.input, s.cachingResolver)
				} else {
					//FIXME CFE assumes that the response of a naming server contains 4 assertions
					//where the last one is of ip4 type
					addr := m.Content[3].(*section.Assertion).Content[0].Value.(string)
					newToken := forwardQuery(*oldMsg, s.input, s.ipToChan[addr], addr, s.continent, s.tld, s.delay)
					delete(s.newTokenToMsg, m.Token)
					s.newTokenToMsg[newToken] = oldMsg
				}
			case *section.Shard, *section.Zone:
				returnToCachingResolver(oldMsg.Token, *m, s.input, s.cachingResolver)
			}
		}
	}
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
}*/

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
