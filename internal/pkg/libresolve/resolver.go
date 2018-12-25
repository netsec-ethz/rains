// Package libresolve implements a recursive and stub resolver for RAINS.
package libresolve

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
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
	RootNameServers []net.Addr
	Forwarders      []net.Addr
	Mode            ResolutionMode
	InsecureTLS     bool
	DialTimeout     time.Duration
	FailFast        bool
	Delegations     *safeHashMap.Map
	Connections     map[net.Addr]net.Conn //FIXME make this map concurency safe, use the connection cache from rainsd
}

//New creates a resolver with the given parameters and default settings
func New(rootNS, forwarders []net.Addr, mode ResolutionMode, addr net.Addr) *Resolver {
	return &Resolver{
		RootNameServers: rootNS,
		Forwarders:      forwarders,
		Mode:            mode,
		InsecureTLS:     defaultInsecureTLS,
		DialTimeout:     defaultTimeout,
		FailFast:        defaultFailFast,
		Delegations:     safeHashMap.New(),
		Connections:     make(map[net.Addr]net.Conn), //TODO fix connection cache to handle this workload
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
func (r *Resolver) ServerLookup(query *query.Name, addr net.Addr, token token.Token) {
	var msg *message.Message
	log.Info("recResolver received query", "query", query, "token", token)
	switch r.Mode {
	case Recursive:
		msg, _ = r.recursiveResolve(query)
	case Forward:
		msg, _ = r.forwardQuery(query)
	default:
		log.Error("Unsupported resolution mode", "mode", r.Mode)
	}
	msg.Token = token
	if conn, ok := r.Connections[addr]; ok {
		log.Info("recResolver answers query", "answer", msg, "token", token, "conn", conn.RemoteAddr(), "resolver", conn.LocalAddr())
		writer := cbor.NewWriter(conn)
		if err := writer.Marshal(msg); err != nil {
			r.createConnAndWrite(addr, msg) //Connection has been closed in the mean time
		}
	} else {
		r.createConnAndWrite(addr, msg)
	}
}

func (r *Resolver) createConnAndWrite(addr net.Addr, msg *message.Message) {
	conn, err := connection.CreateConnection(addr)
	if err != nil {
		log.Error("Was not able to open a connection", "dst", addr)
		return
	}
	r.Connections[addr] = conn
	//FIXME CFE fetch the above function from other repo
	go r.answerDelegQueries(conn)
	writer := cbor.NewWriter(conn)
	if err := writer.Marshal(msg); err != nil {
		log.Error("failed to marshal message", err)
		delete(r.Connections, addr)
	}
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
	//Check for cached delegation assertion
	for _, t := range q.Types {
		if t == object.OTDelegation {
			if a, ok := r.Delegations.Get(q.Name); ok {
				log.Info("respond with a cached delegation", "delegation", a, "query", q)
				return &message.Message{Content: []section.Section{a.(*section.Assertion)}}, nil
			}
			break
		}
	}
	//Start recursive lookup
	for _, root := range r.RootNameServers {
		log.Debug("connecting to root server", "serverAddr", root, "query", q)
		addr := root
		for {
			msg := message.Message{Token: token.New(), Content: []section.Section{q}}
			answer, err := util.SendQuery(msg, addr, r.DialTimeout*time.Millisecond)
			if err != nil || len(answer.Content) == 0 {
				continue
			}
			log.Info("recursive resolver rcv answer", "answer", answer, "query", q)
			isFinal, isRedir, redirMap, srvMap, ipMap := r.handleAnswer(answer, q)
			log.Info("handling answer in recursive lookup", "serverAddr", addr, "isFinal",
				isFinal, "isRedir", isRedir, "redirMap", redirMap, "srvMap", srvMap, "ipMap", ipMap)
			if isFinal {
				return &answer, nil
			} else if isRedir {
				redirTarget, err := followRedirect(redirMap, answer, q.Name)
				if err != nil {
					return nil, err
				}
				if err := updateConnInfo(answer, redirTarget, srvMap, ipMap, addr); err != nil {
					return nil, err
				}
			} else {
				log.Warn("received unexpected answer to query. Recursive lookup cannot be continued",
					"authServer", addr)
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
	ipMap map[string]string, addr net.Addr) (err error) {
	if srvInfo, ok := srvMap[redirTarget]; ok {
		if ipAddr, ok := ipMap[srvInfo.Name]; ok {
			addr, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", ipAddr, srvInfo.Port))
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
			r.Delegations.Add(a.FQDN(), a)
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
		r.handleAssertion(sec, redirMap, srvMap, ipMap, types, name, isFinal, isRedir)
	}
	if strings.HasSuffix(name, z.SubjectZone) {
		*isFinal = true
	}
}

//answerDelegQueries answers delegation queries on conn from its cache. The cache is populated
//through delegations received in a recursive lookup.
func (r *Resolver) answerDelegQueries(conn net.Conn) {
	reader := cbor.NewReader(conn)
	writer := cbor.NewWriter(conn)
	for {
		var msg message.Message
		if err := reader.Unmarshal(&msg); err != nil {
			if err.Error() == "failed to read tag: EOF" {
				log.Info("Connection has been closed", "remoteAddr", conn.RemoteAddr())
			} else {
				log.Warn(fmt.Sprintf("failed to read from client: %v", err))
			}
			delete(r.Connections, conn.RemoteAddr())
			break
		}
		answer := r.getDelegations(msg)
		log.Info("received delegation query. Answer with cached assertions", "query", msg, "assertions", answer)
		msg = message.Message{Token: msg.Token, Content: answer}
		if err := writer.Marshal(&msg); err != nil {
			log.Error("failed to marshal message", err)
			delete(r.Connections, conn.RemoteAddr())
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
					if a, ok := r.Delegations.Get(q.Name); ok {
						answer = append(answer, a.(*section.Assertion))
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
