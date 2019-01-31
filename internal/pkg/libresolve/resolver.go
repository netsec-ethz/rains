// Package libresolve implements a recursive and stub resolver for RAINS.
package libresolve

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/scionproto/scion/go/lib/snet"
)

type ResolutionMode int

const (
	defaultTimeout                     = 10 * time.Second
	defaultFailFast                    = true
	defaultInsecureTLS                 = false
	defaultQueryTimeout                = time.Duration(1000) //in milliseconds
	rainsPrefix                        = "_rains"
	rainsPort                          = uint16(55553)
	tcpPrefix                          = "_tcp"
	udpScionPrefix                     = "_udpscion"
	Recursive           ResolutionMode = iota
	Forward
)

var AllowedAddrTypes = map[object.Type]bool{
	object.OTIP6Addr:    true,
	object.OTIP4Addr:    true,
	object.OTScionAddr6: true,
	object.OTScionAddr4: true,
}
var AllowedRedirectTypes = map[object.Type]bool{
	object.OTIP6Addr:     true,
	object.OTIP4Addr:     true,
	object.OTScionAddr6:  true,
	object.OTScionAddr4:  true,
	object.OTServiceInfo: true,
	object.OTName:        true,
}

// some of these types are not "method expressions" but will be invoked as such
// they (or an interface-based approach) are needed to decouple logic and run tests on different
// parts of the Resolver type

type querySender func(msg message.Message, addr net.Addr, timeout time.Duration) (message.Message, error)
type answerHandler func(r *Resolver, msg message.Message, q *query.Name, recurseCount int) (
	isFinal bool, isRedir bool, redirMap map[string]string, srvMap map[string]object.ServiceInfo,
	ipMap map[string]string, nameMap map[string]object.Name)

// Resolver provides methods to resolve names in RAINS.
type Resolver struct {
	RootNameServers   []net.Addr
	Forwarders        []net.Addr
	Mode              ResolutionMode
	InsecureTLS       bool
	DialTimeout       time.Duration
	FailFast          bool
	Delegations       *safeHashMap.Map
	Connections       cache.Connection
	MaxCacheValidity  util.MaxCacheValidity
	MaxRecursiveCount int
	sendQuery         querySender
	handleAnswer      answerHandler
}

//New creates a resolver with the given parameters and default settings
func New(rootNS, forwarders []net.Addr, rootKeyPath string, mode ResolutionMode, addr net.Addr,
	maxConn int, maxCacheValidity util.MaxCacheValidity, maxRecursiveCount int) (*Resolver, error) {
	r := &Resolver{
		RootNameServers:   rootNS,
		Forwarders:        forwarders,
		Mode:              mode,
		InsecureTLS:       defaultInsecureTLS,
		DialTimeout:       defaultTimeout,
		FailFast:          defaultFailFast,
		Delegations:       safeHashMap.New(),
		Connections:       cache.NewConnection(maxConn),
		MaxCacheValidity:  maxCacheValidity,
		MaxRecursiveCount: maxRecursiveCount,
		// now the pointers to functions
		sendQuery:    util.SendQuery,
		handleAnswer: handleAnswer,
	}
	// load the root zone public key and store it as a delegation:
	a := new(section.Assertion)
	err := util.Load(rootKeyPath, a)
	if err != nil {
		log.Warn("Failed to load root zone public key", "err", err)
		return nil, err
	}
	since, until := util.GetOverlapValidityForSignatures(a.AllSigs())
	a.UpdateValidity(since, until, maxCacheValidity.AssertionValidity)
	pk := a.Content[0].Value.(keys.PublicKey)
	pk.ValidSince = a.ValidSince()
	pk.ValidUntil = a.ValidUntil()
	a.Content[0].Value = pk
	r.Delegations.Add(a.FQDN(), a)
	return r, nil
}

//ClientLookup forwards the query to the specified forwarders or performs a recursive lookup starting at
//the specified root servers. It returns the received information.
func (r *Resolver) ClientLookup(query *query.Name) (*message.Message, error) {
	switch r.Mode {
	case Recursive:
		return r.recursiveResolve(query, 0)
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
	var err error
	log.Info("recResolver received query", "query", query, "token", token)
	switch r.Mode {
	case Recursive:
		msg, err = r.recursiveResolve(query, 0)
	case Forward:
		msg, err = r.forwardQuery(query)
	default:
		log.Error("Unsupported resolution mode", "mode", r.Mode)
		return
	}
	if err != nil {
		log.Error("Query failed", "query failure", err)
		return
	}
	msg.Token = token
	if conn, ok := r.Connections.GetConnection(addr); ok {
		log.Info("recResolver answers query", "answer", msg, "token", token, "conn",
			conn[0].RemoteAddr(), "resolver", conn[0].LocalAddr())
		writer := cbor.NewWriter(conn[0])
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
	r.Connections.AddConnection(conn)
	go r.answerDelegQueries(conn)
	writer := cbor.NewWriter(conn)
	if err := writer.Marshal(msg); err != nil {
		log.Error("failed to marshal message", err)
		r.Connections.CloseAndRemoveConnections(addr)
	}
}

func (r *Resolver) forwardQuery(q *query.Name) (*message.Message, error) {
	if len(r.Forwarders) == 0 {
		return nil, errors.New("forwarders must be specified to use this mode")
	}
	for _, forwarder := range r.Forwarders {
		msg := message.Message{Token: token.New(), Content: []section.Section{q}}
		answer, err := r.sendQuery(msg, forwarder, r.DialTimeout*time.Millisecond)
		if err == nil {
			return &answer, nil
		}
	}
	return nil, fmt.Errorf("could not connect to any of the specified resolver: %v", r.Forwarders)
}

// recursiveResolve starts at the root and follows delegations until it receives an answer.
// It aborts if called more than "recurseCount" times recursively.
func (r *Resolver) recursiveResolve(q *query.Name, recurseCount int) (*message.Message, error) {
	if recurseCount >= r.MaxRecursiveCount {
		return nil, fmt.Errorf("Maximum number of recursive calls reached at %d. Aborting", recurseCount)
	}
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
			answer, err := r.sendQuery(msg, addr, r.DialTimeout*time.Millisecond)
			if err != nil || len(answer.Content) == 0 {
				break
			}
			log.Info("recursive resolver rcv answer", "answer", answer, "query", q)
			isFinal, isRedir, redirMap, srvMap, ipMap, nameMap := r.handleAnswer(r, answer, q, recurseCount)
			log.Info("handling answer in recursive lookup", "serverAddr", addr, "isFinal",
				isFinal, "isRedir", isRedir, "redirMap", redirMap, "srvMap", srvMap, "ipMap", ipMap,
				"nameMap", nameMap)
			if isFinal {
				return &answer, nil
			} else if isRedir {
				for _, name := range redirMap {
					addr, err = r.handleRedirect(name, srvMap, ipMap, nameMap, AllowedRedirectTypes)
					if err == nil {
						break
					}
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

// handleAnswer stores delegation assertions in the delegationCache. It informs the caller if msg
// answers q. It also returns if the msg contains a redirect assertion which indicates that
// another lookup must be performed. Information that is relevant for the next lookup are returned in
// maps.
func handleAnswer(r *Resolver, msg message.Message, q *query.Name, recurseCount int) (isFinal bool, isRedir bool,
	redirMap map[string]string, srvMap map[string]object.ServiceInfo, ipMap map[string]string, nameMap map[string]object.Name) {
	types := make(map[object.Type]bool)
	redirMap = make(map[string]string)
	srvMap = make(map[string]object.ServiceInfo)
	ipMap = make(map[string]string)
	nameMap = make(map[string]object.Name)
	for _, t := range q.Types {
		types[t] = true
	}
	for _, sec := range msg.Content {
		signed, ok := sec.(section.WithSigForward)
		if !ok {
			log.Error("Unexpected Section in Message not of type WithSigForward", "section", sec)
			return
		}
		key, ok := r.Delegations.Get(signed.GetSubjectZone())
		if !ok {
			// key is missing
			keyPhase := 0
			if len(signed.Sigs(keys.RainsKeySpace)) > 0 {
				keyPhase = signed.Sigs(keys.RainsKeySpace)[0].KeyPhase
			} else {
				log.Error("Section does not contain RAINS signatures", "section", sec)
				return
			}
			keyQuery := query.Name{
				Name:        signed.GetSubjectZone(),
				Context:     signed.GetContext(),
				Expiration:  q.Expiration,
				CurrentTime: q.CurrentTime,
				Types:       []object.Type{object.OTDelegation},
				KeyPhase:    keyPhase,
			}
			m, err := r.recursiveResolve(&keyQuery, recurseCount+1)
			if err != nil {
				log.Error("Error trying to obtain public key", "query", keyQuery, "error", err)
				return
			}
			// verify we do have now the key in the cache
			key, ok = r.Delegations.Get(signed.GetSubjectZone())
			if !ok {
				log.Error("Error trying to obtain public key", "subject zone", signed.GetSubjectZone(), "answer", m)
				return
			}
		}
		// we have ensured that key is now an Assertion containing the delegation
		pkeys := make(map[keys.PublicKeyID][]keys.PublicKey)
		for _, k := range (key.(*section.Assertion)).Content {
			pk, isPublicKey := k.Value.(keys.PublicKey)
			if isPublicKey {
				pkeys[pk.PublicKeyID] = append(pkeys[pk.PublicKeyID], pk)
			}
		}
		if !siglib.CheckSectionSignatures(signed, pkeys, r.MaxCacheValidity) {
			log.Error("Section signature invalid!", "section", signed, "public keys", pkeys)
			return
		}
		switch s := sec.(type) {
		case *section.Assertion:
			r.handleAssertion(s, redirMap, srvMap, ipMap, nameMap, types, q.Name, &isFinal, &isRedir)
		case *section.Shard:
			r.handleShard(s, types, q.Name, &isFinal)
		case *section.Zone:
			r.handleZone(s, redirMap, srvMap, ipMap, nameMap, types, q.Name, &isFinal, &isRedir)
		}
	}
	return
}

func (r *Resolver) handleAssertion(a *section.Assertion, redirMap map[string]string,
	srvMap map[string]object.ServiceInfo, ipMap map[string]string, nameMap map[string]object.Name,
	types map[object.Type]bool, name string, isFinal, isRedir *bool) {
	for _, o := range a.Content {
		switch o.Type {
		case object.OTRedirection:
			redirMap[a.FQDN()] = o.Value.(string)
			if _, ok := types[object.OTRedirection]; !ok || a.FQDN() != name {
				*isRedir = true
			}
		case object.OTDelegation:
			// copy the valid times from the assertion to all public keys contained here:
			for i, pk := range a.Content {
				pk, ok := pk.Value.(keys.PublicKey)
				if ok {
					pk.ValidSince = a.ValidSince()
					pk.ValidUntil = a.ValidUntil()
					a.Content[i].Value = pk
				}
			}
			r.Delegations.Add(a.FQDN(), a)
		case object.OTServiceInfo:
			srvMap[a.FQDN()] = o.Value.(object.ServiceInfo)
		case object.OTIP6Addr:
			ipMap[a.FQDN()] = o.Value.(string)
		case object.OTIP4Addr:
			ipMap[a.FQDN()] = o.Value.(string)
		case object.OTScionAddr6:
			ipMap[a.FQDN()] = o.Value.(string)
		case object.OTScionAddr4:
			ipMap[a.FQDN()] = o.Value.(string)
		case object.OTName:
			nameMap[a.FQDN()] = o.Value.(object.Name)
		}
		if _, ok := types[o.Type]; ok && a.FQDN() == name {
			*isFinal = true
		}
	}
}

//handleShard checks if s is an answer to the query. Note that a shard containing a positive answer
//for the query is considered answering it although this is not allowed by the protocol. The caller
//is responsible for checking this property.
func (r *Resolver) handleShard(s *section.Shard, types map[object.Type]bool, name string, isFinal *bool) {
	if strings.HasSuffix(name, s.SubjectZone) && s.InRange(strings.TrimSuffix(name, s.SubjectZone)) {
		*isFinal = true
	}
}

//handleZone checks if z or the contained assertions are an answer to the query.
func (r *Resolver) handleZone(z *section.Zone, redirMap map[string]string,
	srvMap map[string]object.ServiceInfo, ipMap map[string]string, nameMap map[string]object.Name,
	types map[object.Type]bool, name string, isFinal, isRedir *bool) {
	for _, sec := range z.Content {
		r.handleAssertion(sec, redirMap, srvMap, ipMap, nameMap, types, name, isFinal, isRedir)
	}
	if strings.HasSuffix(name, z.SubjectZone) {
		*isFinal = true
	}
}

func (r *Resolver) handleRedirect(name string, srvMap map[string]object.ServiceInfo,
	ipMap map[string]string, nameMap map[string]object.Name, allowedTypes map[object.Type]bool) (
	net.Addr, error) {
	if allowedTypes[object.OTIP6Addr] || allowedTypes[object.OTIP4Addr] {
		if ipAddr, ok := ipMap[name]; ok {
			return net.ResolveTCPAddr("", fmt.Sprintf("%s:%d", ipAddr, rainsPort))
		}
	}
	if allowedTypes[object.OTScionAddr6] || allowedTypes[object.OTScionAddr4] {
		if ipAddr, ok := ipMap[name]; ok {
			return snet.AddrFromString(fmt.Sprintf("%s:%d", ipAddr, rainsPort))
		}
	}
	if allowedTypes[object.OTServiceInfo] && strings.HasPrefix(name, rainsPrefix) {
		if srvVal, ok := srvMap[name]; ok {
			if addr, err := r.handleRedirect(srvVal.Name, srvMap, ipMap, nameMap,
				AllowedAddrTypes); err == nil {
				ip := strings.Split(addr.String(), ":")[0]
				return net.ResolveTCPAddr("", fmt.Sprintf("%s:%d", ip, srvVal.Port))
			}
		}
	}
	if allowedTypes[object.OTName] {
		if nameVal, ok := nameMap[name]; ok {
			allowTypes := make(map[object.Type]bool)
			for _, t := range nameVal.Types {
				allowTypes[t] = true
			}
			if as, err := r.handleRedirect(nameVal.Name, srvMap, ipMap, nameMap,
				allowTypes); err == nil {
				return as, nil
			}
		}
	}
	return nil, fmt.Errorf("redir name did not end in a host addr. redirName=%s", name)
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
			r.Connections.CloseAndRemoveConnection(conn)
			break
		}
		answer := r.getDelegations(msg)
		log.Info("received delegation query. Answer with cached assertions", "query", msg, "assertions", answer)
		msg = message.Message{Token: msg.Token, Content: answer}
		if err := writer.Marshal(&msg); err != nil {
			log.Error("failed to marshal message", err)
			r.Connections.CloseAndRemoveConnection(conn)
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
