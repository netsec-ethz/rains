// Package libresolve implements a recursive and stub resolver for RAINS.
package resolver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/util"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
)

type ResolutionMode int

var (
	defaultTimeout  = 10 * time.Second
	defaultFailFast = true
)

const (
	ResolutionModeRecursive ResolutionMode = iota
	ResolutionModeForwarding
)

// Server provides methods to resolve names in RAINS.
type Server struct {
	RootNameservers []string
	Forwarders      []string
	Mode            ResolutionMode
	InsecureTLS     bool
	DialTimeout     time.Duration
	FailFast        bool
}

func New(rootNS, forwarders []string, mode ResolutionMode, insecureTLS bool) *Server {
	return &Server{
		RootNameservers: rootNS,
		Forwarders:      forwarders,
		Mode:            mode,
		InsecureTLS:     insecureTLS,
		DialTimeout:     defaultTimeout,
		FailFast:        defaultFailFast,
	}
}

func (r *Server) Lookup(name, context string) (*message.RainsMessage, error) {
	switch r.Mode {
	case ResolutionModeRecursive:
		return r.recursiveResolve(name, context)
	case ResolutionModeForwarding:
		q := r.nameToQuery(name, context, time.Now().Add(15*time.Second).UnixNano(), []sections.QueryOption{})
		return r.forwardQuery(q)
	default:
		return nil, fmt.Errorf("Unsupported resolution mode: %v", r.Mode)
	}
}

func (r *Server) nameToQuery(name, context string, expTime int64, opts []sections.QueryOption) message.RainsMessage {
	types := []object.ObjectType{object.OTIP4Addr, object.OTIP6Addr, object.OTDelegation, object.OTServiceInfo, object.OTRedirection}
	return util.NewQueryMessage(name, context, expTime, types, opts, token.GenerateToken())
}

// listen waits for one message and passes it back on the provided channel, or an error on the error channel.
func listen(conn net.Conn, tok token.Token, done chan<- *message.RainsMessage, ec chan<- error) {
	reader := borat.NewCBORReader(conn)
	var msg message.RainsMessage
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

func (r *Server) forwardQuery(q message.RainsMessage) (*message.RainsMessage, error) {
	if len(r.Forwarders) == 0 {
		return nil, errors.New("forwarders must be specified to use this mode")
	}
	errs := make([]error, 0)
	for i, forwarder := range r.Forwarders {
		log.Info(fmt.Sprintf("Connecting to forwarding resolver #%d: %v", i, forwarder))
		d := &net.Dialer{
			Timeout: r.DialTimeout,
		}
		conn, err := tls.DialWithDialer(d, "tcp", forwarder, &tls.Config{InsecureSkipVerify: r.InsecureTLS})
		if err != nil {
			log.Warn(fmt.Sprintf("Connection to fowarding resolver %d failed: %v", i, err))
			errs = append(errs, err)
			continue
		}
		defer conn.Close()
		writer := borat.NewCBORWriter(conn)
		if err := writer.Marshal(q); err != nil {
			errs = append(errs, fmt.Errorf("failed to marshal message to server: %v", err))
			continue
		}
		done := make(chan *message.RainsMessage)
		ec := make(chan error)
		go listen(conn, q.Token, done, ec)
		select {
		case msg := <-done:
			return msg, nil
		case err := <-ec:
			return nil, err
		}
	}
	return nil, fmt.Errorf("could not connect to any specified resolver, errors: %v", errs)
}

func mergeSubjectZone(subject, zone string) string {
	if zone == "." {
		return fmt.Sprintf("%s.", subject)
	}
	if subject == "" {
		return zone
	}
	return fmt.Sprintf("%s.%s", subject, zone)
}

func NameToLabels(name string) ([]string, error) {
	if !strings.HasSuffix(name, ".") {
		return nil, fmt.Errorf("domain name must end with root qualifier '.', got %s", name)
	}
	parts := strings.Split(name, ".")
	// Last element is empty because of root dot, so discard it.
	return parts[:len(parts)-1], nil
}

// recursiveResolve starts at the root and follows delegations until it receives an answer.
func (r *Server) recursiveResolve(name, context string) (*message.RainsMessage, error) {
	latestResolver := r.RootNameservers[0] // TODO: try multiple root nameservers.
	var resp *message.RainsMessage
	for {
		log.Info(fmt.Sprintf("connecting to resolver at address: %s to resolve %q", latestResolver, name))
		d := &net.Dialer{
			Timeout: r.DialTimeout,
		}
		conn, err := tls.DialWithDialer(d, "tcp", latestResolver, &tls.Config{InsecureSkipVerify: r.InsecureTLS})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to resolver: %v", err)
		}
		defer conn.Close()
		writer := borat.NewCBORWriter(conn)
		q := r.nameToQuery(name, context, time.Now().Add(15*time.Second).Unix(), []sections.QueryOption{})
		if err := writer.Marshal(&q); err != nil {
			return nil, fmt.Errorf("failed to marshal query to server: %v", err)
		}
		done := make(chan *message.RainsMessage)
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
		for _, section := range resp.Content {
			switch section.(type) {
			case *sections.ZoneSection:
				// If we were given a whole zone it's because we asked for it or it's non-existance proof.
				return resp, nil
			case *sections.AssertionSection:
				as := section.(*sections.AssertionSection)
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
			case *sections.ShardSection:
				return resp, nil
			default:
				return nil, fmt.Errorf("got unknown type: %T", section)
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
