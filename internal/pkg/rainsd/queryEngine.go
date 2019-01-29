package rainsd

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cache"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

const (
	rainsSrvPrefix = "_rains."
)

//processQuery processes msgSender containing a query section
func (s *Server) processQuery(msgSender util.MsgSectionSender) {
	queries := []*query.Name{}
	for _, sec := range msgSender.Sections {
		if q, ok := sec.(*query.Name); ok {
			queries = append(queries, q)
		} else {
			log.Error("Not supported query message section. This case must be prevented beforehand")
			return
		}
	}
	if len(s.config.Authorities) == 0 {
		//caching resolver
		answerQueriesCachingResolver(msgSender, s)
	} else {
		//naming server
		answerQueriesAuthoritative(queries, msgSender.Sender, msgSender.Token, s)
	}
}

//answerQueryCachingResolver is how a caching resolver answers queries
func answerQueriesCachingResolver(ss util.MsgSectionSender, s *Server) {
	log.Info("Start processing query as cr", "queries", ss.Sections)
	queries := []*query.Name{}
	sections := []section.Section{}
	for _, q := range ss.Sections {
		q := q.(*query.Name)
		if secs := cacheLookup(q, ss.Sender, ss.Token, s); secs != nil {
			sections = append(sections, secs...)
		} else {
			queries = append(queries, q)
		}
	}
	if len(queries) == 0 {
		sendSections(sections, ss.Token, ss.Sender, s)
		return
	}

	log.Debug("Not all queries have a cached answer", "token", ss.Token)
	tok := ss.Token
	if !ss.Sections[0].(*query.Name).ContainsOption(query.QOTokenTracing) {
		tok = token.New()
	}
	validUntil := time.Now().Add(s.config.QueryValidity).Unix() //Upper bound for forwarded query expiration time
	for _, q := range queries {
		if q.Expiration < validUntil {
			validUntil = q.Expiration
		}
	}
	log.Info("Adding sectionSender to pending query cache", "sectionSender", ss)
	if isNew := s.caches.PendingQueries.Add(ss, tok, validUntil); isNew {
		log.Info("Forwarding queries to recursive resolver", "queries", queries)
		qs := []section.Section{}
		for _, q := range queries {
			q.Expiration = validUntil
			qs = append(qs, q)
		}
		s.sendToRecursiveResolver(message.Message{Token: tok, Content: qs})
	} else {
		log.Info("Query has already been sent to recursive resolver", "queries", queries)
	}
}

//answerQueryAuthoritative is how an authoritative server answers queries
func answerQueriesAuthoritative(qs []*query.Name, sender net.Addr, token token.Token, s *Server) {
	log.Info("Start processing query as authority", "queries", qs)
	for _, q := range qs {
		for i, auth := range s.config.Authorities {
			if strings.HasSuffix(q.Name, auth.Zone) && q.Context == auth.Context {
				break
			}
			if i == len(s.config.Authorities)-1 {
				log.Info("Query is not about a name this zone has authority over", "name", q.Name,
					"authorities", s.config.Authorities)
				return
			}
		}
	}

	queries := []*query.Name{}
	sections := []section.Section{}
	for _, q := range qs {
		if secs := cacheLookup(q, sender, token, s); secs != nil {
			sections = append(sections, secs...)
		} else {
			queries = append(queries, q)
		}
	}

	if len(queries) != 0 {
		//glueRecordNames assumes that the names of delegates do not contain a dot '.'.
		names := glueRecordNames(queries, s.config.Authorities)
		for name := range names {
			glueRecords, err := glueRecordLookup(name.Zone, name.Context, s.caches.AssertionsCache)
			if err != nil {
				log.Warn("Was not able to find all glue records.", "name", name, "error", err.Error())
				return
			}
			sections = append(sections, glueRecords...)
		}
	}
	sendSections(sections, token, sender, s)
	log.Info("Finished handling query by sending records from cache", "queries", qs,
		"sections", sections)
}

//cacheLookup answers q with a cached entry if there is one. True is returned in case of a cache hit
func cacheLookup(q *query.Name, sender net.Addr, token token.Token, s *Server) []section.Section {
	assertions := assertionCacheLookup(q, s)
	if len(assertions) > 0 {
		return assertions
	}

	log.Debug("No direct entry found in assertion cache.", "name", q.Name,
		"context", q.Context, "type", q.Types)
	//negative answer lookup (note that it can occur a positive answer if assertion removed from cache)
	sections := negativeCacheLookup(q, sender, token, s)
	if len(sections) > 0 {
		return sections
	}
	return nil
}

func assertionCacheLookup(q *query.Name, s *Server) (assertions []section.Section) {
	assertionSet := make(map[string]bool)
	asKey := func(a *section.Assertion) string {
		return fmt.Sprintf("%s_%s_%s", a.SubjectName, a.SubjectZone, a.Context)
	}

	for _, t := range q.Types {
		if asserts, ok := s.caches.AssertionsCache.Get(q.Name, q.Context, t, true); ok {
			for _, a := range asserts {
				if _, ok := assertionSet[asKey(a)]; ok {
					continue
				}
				if a.ValidUntil() > time.Now().Unix() {
					log.Debug(fmt.Sprintf("appending valid assertion: %v", a))
					assertions = append(assertions, a)
					assertionSet[asKey(a)] = true
				}
			}
		}
	}
	return
}

func negativeCacheLookup(q *query.Name, sender net.Addr, token token.Token, s *Server) []section.Section {
	subject, zone, err := toSubjectZone(q.Name)
	if err != nil {
		sendNotificationMsg(token, sender, section.NTRcvInconsistentMsg,
			"query name must end with root zone dot '.'", s)
		log.Warn("failed to concert query name to subject and zone", "error", err)
		return nil
	}
	answer, _ := s.caches.NegAssertionCache.Get(zone, q.Context, section.StringInterval{Name: subject})
	return filterAnswer(answer)
}

func filterAnswer(sections []section.WithSigForward) (answer []section.Section) {
	//TODO CFE For each type check if one of the zone or shards contain the queried
	//assertion. If there is at least one assertion answer with it. If no assertion is
	//contained in a zone or shard for any of the queried connection, answer with the shortest
	//element. shortest according to what? size in bytes? how to efficiently determine that.
	//e.g. using gob encoding. alternatively we could also count the number of contained
	//elements.
	for _, s := range sections {
		answer = append(answer, s)
	}
	return
}

//glueRecordNames returns the unique names for which glue records should be looked up based on qs.
//It assumes that the names of all delegates do not contain a dot '.'.
func glueRecordNames(qs []*query.Name, zoneAuths []ZoneContext) map[ZoneContext]bool {
	result := make(map[ZoneContext]bool)
	for _, q := range qs {
		for _, auth := range zoneAuths {
			if strings.HasSuffix(q.Name, auth.Zone) {
				name := strings.TrimSuffix(q.Name, auth.Zone)
				names := strings.Split(name, ".")
				if names[len(names)-1] == "" {
					name = fmt.Sprintf("%s.%s", names[len(names)-2], auth.Zone)
				} else { //root zone
					name = names[len(names)-1] + auth.Zone
				}
				result[ZoneContext{name, q.Context}] = true
			}
		}
	}
	return result
}

func glueRecordLookup(name, context string, cache cache.Assertion) ([]section.Section, error) {
	var assertions []section.Section
	asserts, ok := cache.Get(name, context, object.OTDelegation, true)
	if !ok {
		return nil, errors.New("no delegation assertion found")
	}
	for _, a := range asserts {
		assertions = append(assertions, a) //append delegations
	}

	//Follow redirect and get all assertions along the way
	asserts, ok = cache.Get(name, context, object.OTRedirection, true) //returns cached redirect assertions in random order
	if !ok {
		return nil, errors.New("no redirect assertion found")
	}
	for _, a := range asserts {
		for _, o := range a.Content {
			if o.Type == object.OTRedirection {
				if answers, err := handleRedirect(o.Value.(string), context, cache,
					allAllowedTypes()); err == nil {
					assertions = append(assertions, a) //append redir
					for _, answer := range answers {
						assertions = append(assertions, answer) //append addr, and if necessary srv and/or names.
					}
					return assertions, nil
				}
			}
		}
	}
	return nil, errors.New("no redir ended in a host addr")
}

func allAllowedTypes() map[object.Type]bool {
	return map[object.Type]bool{
		object.OTIP6Addr:     true,
		object.OTIP4Addr:     true,
		object.OTServiceInfo: true,
		object.OTName:        true,
	}
}

func allowedAddrTypes() map[object.Type]bool {
	return map[object.Type]bool{
		object.OTIP6Addr: true,
		object.OTIP4Addr: true,
	}
}

func handleRedirect(name, context string, cache cache.Assertion, allowedTypes map[object.Type]bool) ([]*section.Assertion, error) {
	if allowedTypes[object.OTIP6Addr] {
		if asserts, ok := cache.Get(name, context, object.OTIP6Addr, true); ok {
			return asserts, nil
		}
	}
	if allowedTypes[object.OTIP4Addr] {
		if asserts, ok := cache.Get(name, context, object.OTIP4Addr, true); ok {
			return asserts, nil
		}
	}
	//TODO add scion addr types
	if allowedTypes[object.OTServiceInfo] && strings.HasPrefix(name, rainsSrvPrefix) {
		if asserts, ok := cache.Get(name, context, object.OTServiceInfo, true); ok {
			for _, srv := range asserts {
				for _, srvObj := range srv.Content {
					if srvObj.Type == object.OTServiceInfo {
						srvVal := srvObj.Value.(object.ServiceInfo)
						if as, err := handleRedirect(srvVal.Name, context, cache,
							allowedAddrTypes()); err == nil {
							return append(as, srv), nil
						}
					}
				}
			}
		}
	}
	if allowedTypes[object.OTName] {
		if asserts, ok := cache.Get(name, context, object.OTName, true); ok {
			for _, name := range asserts {
				for _, nameObj := range name.Content {
					if nameObj.Type == object.OTName {
						nameVal := nameObj.Value.(object.Name)
						allowTypes := make(map[object.Type]bool)
						for _, t := range nameVal.Types {
							allowTypes[t] = true
						}
						if as, err := handleRedirect(nameVal.Name, context, cache,
							allowTypes); err == nil {
							return append(as, name), nil
						}
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("redir name did not end in a host addr. redirName=%s", name)
}

// toSubjectZone splits a name into a subject and zone.
// Invariant: name always ends with the '.'.
func toSubjectZone(name string) (subject, zone string, e error) {
	if !strings.HasSuffix(name, ".") {
		return "", "", fmt.Errorf("invariant that query name ends with '.' is broken: %v", name)
	}
	parts := strings.Split(name, ".")
	if parts[0] == "" {
		zone = "."
		subject = ""
		return
	}
	subject = parts[0]
	zone = strings.Join(parts[1:], ".")

	log.Debug("Split into zone and name", "subject", subject, "zone", zone)
	return
}
