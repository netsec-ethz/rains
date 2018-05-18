// Package libresolve implements a recursive and stub resolver for RAINS.
package libresolve

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/netsec-ethz/rains/rainslib"
	"github.com/netsec-ethz/rains/utils/protoParser"
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

// Resolver provides methods to resolve names in RAINS.
type Resolver struct {
	RootNameservers []string
	Forwarders      []string
	Mode            ResolutionMode
	InsecureTLS     bool
	DialTimeout     time.Duration
	FailFast        bool
}

func New(rootNS, forwarders []string, mode ResolutionMode, insecureTLS bool) *Resolver {
	return &Resolver{
		RootNameservers: rootNS,
		Forwarders:      forwarders,
		Mode:            mode,
		InsecureTLS:     insecureTLS,
		DialTimeout:     defaultTimeout,
		FailFast:        defaultFailFast,
	}
}

func (r *Resolver) Lookup(name, context string) (*rainslib.RainsMessage, error) {
	switch r.Mode {
	case ResolutionModeRecursive:
		return r.recursiveResolve(name, context)
	case ResolutionModeForwarding:
		q := r.nameToQuery(name, context, time.Now().Add(15*time.Second).UnixNano(), []rainslib.QueryOption{})
		return r.forwardQuery(q)
	default:
		panic(fmt.Sprintf("Unsupported resolution mode: %v", r.Mode))
	}
}

func (r *Resolver) nameToQuery(name, context string, expTime int64, opts []rainslib.QueryOption) rainslib.RainsMessage {
	types := []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr, rainslib.OTDelegation, rainslib.OTServiceInfo, rainslib.OTRedirection}
	return rainslib.NewQueryMessage(name, context, expTime, types, opts, rainslib.GenerateToken())
}

// waitResponse listens on the given parserframer until a message with the
// specified token is received. If there is an error, it will be sent on
// the error channel.
func (r *Resolver) waitResponse(pf protoParser.ProtoParserAndFramer, token rainslib.Token, done chan *rainslib.RainsMessage, ec chan error) {
	for pf.DeFrame() {
		tok, err := pf.Token(pf.Data())
		if err != nil {
			ec <- fmt.Errorf("failed to get token from message: %v", err)
			if r.FailFast {
				return
			}
		}
		msg, err := pf.Decode(pf.Data())
		if err != nil {
			ec <- fmt.Errorf("failed to parse bytes to RAINS message: %v", err)
			if r.FailFast {
				return
			}
		}
		if tok != token {
			ec <- fmt.Errorf("expected message with token %v but got %v", token, tok)
			if r.FailFast {
				return
			}
		} else {
			done <- &msg
			return
		}
	}
}

func (r *Resolver) forwardQuery(q rainslib.RainsMessage) (*rainslib.RainsMessage, error) {
	if len(r.Forwarders) == 0 {
		return nil, errors.New("forwarders must be specified to use this mode.")
	}
	errs := make([]error, 0)
	for i, forwarder := range r.Forwarders {
		glog.Infof("Connecting to forwarding resolver #%d: %v", i, forwarder)
		d := &net.Dialer{
			Timeout: r.DialTimeout,
		}
		conn, err := tls.DialWithDialer(d, "tcp", forwarder, &tls.Config{InsecureSkipVerify: r.InsecureTLS})
		if err != nil {
			glog.Warningf("Connection to fowarding resolver %d failed: %v", i, err)
			errs = append(errs, err)
			continue
		}
		defer conn.Close()
		pf := protoParser.ProtoParserAndFramer{}
		pf.InitStreams(conn, conn)
		b, err := pf.Encode(q)
		if err != nil {
			return nil, fmt.Errorf("failed to encode message: %v", err)
		}
		if err := pf.Frame(b); err != nil {
			return nil, fmt.Errorf("failed to frame message: %v", err)
		}
		done := make(chan *rainslib.RainsMessage)
		ec := make(chan error)
		go r.waitResponse(pf, q.Token, done, ec)
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
func (r *Resolver) recursiveResolve(name, context string) (*rainslib.RainsMessage, error) {
	latestResolver := r.RootNameservers[0] // TODO: try multiple root nameservers.
	var resp *rainslib.RainsMessage
	for {
		glog.Infof("connecting to resolver at address: %s to resolve %q", latestResolver, name)
		d := &net.Dialer{
			Timeout: r.DialTimeout,
		}
		conn, err := tls.DialWithDialer(d, "tcp", latestResolver, &tls.Config{InsecureSkipVerify: r.InsecureTLS})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to resolver: %v", err)
		}
		defer conn.Close()
		pf := protoParser.ProtoParserAndFramer{}
		pf.InitStreams(conn, conn)
		q := r.nameToQuery(name, context, time.Now().Add(15*time.Second).Unix(), []rainslib.QueryOption{})
		glog.Infof("query is: %v", q)
		b, err := pf.Encode(q)
		if err != nil {
			return nil, fmt.Errorf("failed to encode query: %v", err)
		}
		if err := pf.Frame(b); err != nil {
			return nil, fmt.Errorf("failed to frame message: %v", err)
		}
		done := make(chan *rainslib.RainsMessage)
		ec := make(chan error)
		go r.waitResponse(pf, q.Token, done, ec)
		select {
		case msg := <-done:
			resp = msg
		case err := <-ec:
			return nil, err
		}
		if len(resp.Content) == 0 {
			return nil, errors.New("got empty response")
		}
		glog.Infof("response was %+v", resp)
		// The response can either be a redirection chain or a response.
		redirectMap := make(map[string]string)
		srvMap := make(map[string]rainslib.ServiceInfo)
		concreteMap := make(map[string]string)
		for _, section := range resp.Content {
			switch section.(type) {
			case *rainslib.AssertionSection:
				as := section.(*rainslib.AssertionSection)
				sz := mergeSubjectZone(as.SubjectName, as.SubjectZone)
				if sz == name {
					return resp, nil
				}
				for _, obj := range as.Content {
					switch obj.Type {
					case rainslib.OTRedirection:
						redirectMap[sz] = obj.Value.(string)
					case rainslib.OTServiceInfo:
						si := obj.Value.(rainslib.ServiceInfo)
						srvMap[sz] = si
					case rainslib.OTIP4Addr:
						concreteMap[sz] = obj.Value.(string)
					case rainslib.OTIP6Addr:
						concreteMap[sz] = fmt.Sprintf("[%s]", obj.Value.(string))
					}
				}
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
