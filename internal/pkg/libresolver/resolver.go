// Package libresolve implements a recursive and stub resolver for RAINS.
package libresolve

import (
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
	var msg *message.Message
	switch r.Mode {
	case Recursive:
		msg, _ = r.recursiveResolve(query)
	case Forward:
		msg, _ = r.forwardQuery(query)
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

func (r *Resolver) createConnAndWrite(connInfo connection.Info, msg *message.Message) {
	conn, err := connection.CreateConnection(connInfo)
	if err != nil {
		log.Error("Was not able to open a connection", "dst", connInfo)
		return
	}
	r.Connections[connInfo] = conn
	go r.answerDelegQueries(conn, connInfo)
	writer := cbor.NewWriter(conn)
	if err := writer.Marshal(msg); err != nil {
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
			isFinal, isRedir, redirMap, srvMap, ipMap := r.handleAnswer(msg, q)
			if isFinal {
				return &msg, nil
			} else if isRedir {
				redirTarget, err := followRedirect(redirMap, msg, q.Name)
				if err != nil {
					return nil, err
				}
				if err := updateConnInfo(msg, redirTarget, srvMap, ipMap, &connInfo); err != nil {
					return nil, err
				}
			} else {
				log.Warn("received unexpected answer to query. Recursive lookup cannot be continued",
					"authServer", connInfo)
				break
			}
		}
	}
	return nil, fmt.Errorf("Was not able to obtain an answer through a recursive lookup for query: %s",
		q.String())
}

//followRedirect returns the last name of the redirect chain which should have a corresponding
//service information object
func followRedirect(redirMap map[string]string, msg message.Message, name string) (string, error) {
	// Check if there is a redirection for a suffix we are interested in.
	redirTarget := ""
	for key, value := range redirMap {
		if strings.HasSuffix(name, key) {
			redirTarget = value
			break
		}
	}
	if redirTarget == "" {
		return "", fmt.Errorf("failed to find result or redirection, response was: %v", msg)
	}

	// Follow redir until we encounter a srv.
	seen := make(map[string]bool)
	for {
		if _, ok := seen[redirTarget]; ok {
			return "", fmt.Errorf("redirect loop detected, target %q, response: %v", redirTarget, msg)
		}
		seen[redirTarget] = true
		if next, ok := redirMap[redirTarget]; ok {
			redirTarget = next
		} else {
			break
		}
	}
	return redirTarget, nil
}

//updateConnInfo changes connInfo to match the next hop in the recursive lookup. If not sufficient
//information is available, an error is returned
func updateConnInfo(msg message.Message, redirTarget string, srvMap map[string]object.ServiceInfo,
	ipMap map[string]string, connInfo *connection.Info) (err error) {
	if srvInfo, ok := srvMap[redirTarget]; ok {
		if ipAddr, ok := ipMap[srvInfo.Name]; ok {
			connInfo.TCPAddr, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", ipAddr, srvInfo.Port))
			if err != nil {
				return fmt.Errorf("received IP address or port is malformed: %v", msg)
			}
		} else {
			return fmt.Errorf(
				"serviceInfo target could not be found in response, target: %q, response: %v",
				srvInfo.Name, msg)
		}
	} else {
		return fmt.Errorf(
			"received incomplete response, missing serviceInfo for target FQDN %q, response: %v",
			redirTarget, msg)
	}
	return
}

//handleAnswer stores delegation assertions in the delegationCache. It informs the caller if msg
//answers q. It also returns if the msg contains a redirect assertion which indicates that
//another lookup must be performed. Information that is relevant for the next lookup are returned in
//maps.
func (r *Resolver) handleAnswer(msg message.Message, q *query.Name) (isFinal bool, isRedir bool,
	redirMap map[string]string, srvMap map[string]object.ServiceInfo, ipMap map[string]string) {
	types := make(map[object.Type]bool)
	redirMap = make(map[string]string)
	srvMap = make(map[string]object.ServiceInfo)
	ipMap = make(map[string]string)
	for _, t := range q.Types {
		types[t] = true
	}
	for _, sec := range msg.Content {
		//FIXME check signature of sections and request delegations if necessary
		switch s := sec.(type) {
		case *section.Assertion:
			r.handleAssertion(s, redirMap, srvMap, ipMap, types, q.Name, &isFinal, &isRedir)
		case *section.Shard:
			handleShard(s, types, q.Name, &isFinal)
		case *section.Zone:
			r.handleZone(s, redirMap, srvMap, ipMap, types, q.Name, &isFinal, &isRedir)
		}
	}
	return
}

func (r *Resolver) handleAssertion(a *section.Assertion, redirMap map[string]string,
	srvMap map[string]object.ServiceInfo, ipMap map[string]string, types map[object.Type]bool,
	name string, isFinal, isRedir *bool) {
	for _, o := range a.Content {
		switch o.Type {
		case object.OTRedirection:
			redirMap[a.FQDN()] = o.Value.(string)
			if _, ok := types[object.OTRedirection]; !ok || a.FQDN() != name {
				*isRedir = true
			}
		case object.OTDelegation:
			r.Delegations[a.FQDN()] = a
		case object.OTServiceInfo:
			srvMap[a.FQDN()] = o.Value.(object.ServiceInfo)
		case object.OTIP6Addr:
			ipMap[a.FQDN()] = o.Value.(string)
		case object.OTIP4Addr:
			ipMap[a.FQDN()] = o.Value.(string)
		}
		if _, ok := types[o.Type]; ok && a.FQDN() == name {
			*isFinal = true
		}
	}
}

//handleShard checks if s is an answer to the query. Note that a shard containing a positive answer
//for the query is considered answering it although this is not allowed by the protocol. The caller
//is responsible for checking this property.
func handleShard(s *section.Shard, types map[object.Type]bool, name string, isFinal *bool) {
	if strings.HasSuffix(name, s.SubjectZone) && s.InRange(strings.TrimSuffix(name, s.SubjectZone)) {
		*isFinal = true
	}
}

//handleZone checks if z or the contained assertions are an answer to the query.
func (r *Resolver) handleZone(z *section.Zone, redirMap map[string]string,
	srvMap map[string]object.ServiceInfo, ipMap map[string]string, types map[object.Type]bool,
	name string, isFinal, isRedir *bool) {
	for _, sec := range z.Content {
		switch s := sec.(type) {
		case *section.Assertion:
			r.handleAssertion(s, redirMap, srvMap, ipMap, types, name, isFinal, isRedir)
		case *section.Shard:
		default:
			log.Warn("zone contains invalid section type", "sec", sec)
		}
	}
	if strings.HasSuffix(name, z.SubjectZone) {
		*isFinal = true
	}
}
