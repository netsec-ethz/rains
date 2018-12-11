package rainsd

import (
	"fmt"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//processQuery processes msgSender containing a query section
func (s *Server) processQuery(msgSender msgSectionSender) {
	switch section := msgSender.Section.(type) {
	case *query.Name:
		if len(s.config.ZoneAuthority) == 0 {
			//caching resolver
			answerQueryCachingResolver(section, msgSender.Sender, msgSender.Token, s)
		} else {
			//naming server
			answerQueryAuthoritative(section, msgSender.Sender, msgSender.Token, s)
		}
	default:
		log.Error("Not supported query message section. This case must be prevented beforehand")
	}
}

//answerQueryAuthoritative is how an authoritative server answers queries
func answerQueryAuthoritative(q *query.Name, sender connection.Info, token token.Token, s *Server) {
	log.Debug("Start processing query", "query", q)
	//FIXME CFE make it work with several authority zones and with context
	if !strings.HasSuffix(q.Name, s.config.ZoneAuthority[0]) {
		log.Info("Query is not about a name this zone has authority over", "name", q.Name, "authority", s.config.ZoneAuthority[0])
		return
	}

	assertions := assertionCacheLookup(q, s)
	if len(assertions) > 0 {
		sendSections(assertions, token, sender, s)
		log.Info("Finished handling query by sending assertion from cache", "query", q,
			"answer", assertions)
		return
	}

	log.Debug("No direct entry found in assertion cache.", "name", q.Name,
		"context", q.Context, "type", q.Types)
	//negative answer lookup (note that it can occur a positive answer if assertion removed from cache)
	sections := negativeCacheLookup(q, sender, token, s)
	if len(sections) > 0 {
		//TODO CFE For each type check if one of the zone or shards contain the queried
		//assertion. If there is at least one assertion answer with it. If no assertion is
		//contained in a zone or shard for any of the queried connection, answer with the shortest
		//element. shortest according to what? size in bytes? how to efficiently determine that.
		//e.g. using gob encoding. alternatively we could also count the number of contained
		//elements.
		sendSection(sections[0], token, sender, s)
		trace(token, fmt.Sprintf("found negative assertion matching query: %v", sections[0]))
		log.Info("Finished handling query by sending shard or zone from cache", "query", q)
		return
	}

	log.Debug("No entry found in negAssertion cache directly matching the query")
	log.Debug("Fetch glue records")
	glueRecords := glueRecordLookup(q, s)
	if len(glueRecords) < 4 {
		log.Warn("Not enough matching glue records")
		return
	}
	sendSections(assertions, token, sender, s)
	log.Info("Finished handling query by sending glue records from cache", "query", q)
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

func negativeCacheLookup(q *query.Name, sender connection.Info, token token.Token, s *Server) []section.WithSigForward {
	subject, zone, err := toSubjectZone(q.Name)
	if err != nil {
		sendNotificationMsg(token, sender, section.NTRcvInconsistentMsg,
			"query name must end with root zone dot '.'", s)
		log.Warn("failed to concert query name to subject and zone", "error", err)
		return nil
	}
	answer, _ := s.caches.NegAssertionCache.Get(zone, q.Context, section.StringInterval{Name: subject})
	return answer
}

func glueRecordLookup(q *query.Name, s *Server) (assertions []section.Section) {
	types := []object.Type{object.OTDelegation, object.OTRedirection, object.OTServiceInfo, object.OTIP4Addr}
	name := strings.TrimSuffix(q.Name, s.config.ZoneAuthority[0])
	names := strings.Split(name, ".")
	if names[len(names)-1] == "" {
		name = fmt.Sprintf("%s.%s", names[len(names)-2], s.config.ZoneAuthority[0])
	} else {
		name = names[len(names)-1] + s.config.ZoneAuthority[0]
	}
	names = []string{name, name, "ns." + name, "ns1." + name}
	for i, t := range types {
		if asserts, ok := s.caches.AssertionsCache.Get(names[i], q.Context, t, false); !ok {
			log.Error("No glue record in cache!", "Name", names[i], "Type", t)
		} else {
			assertions = append(assertions, asserts[0]) //FIXME CFE, handle if there are more assertions in response
		}
	}
	return
}

//answerQueryCachingResolver is how a caching resolver answers queries
func answerQueryCachingResolver(q *query.Name, sender connection.Info, oldToken token.Token, s *Server) {
	log.Debug("Start processing query", "query", q)

	assertions := assertionCacheLookup(q, s)
	if len(assertions) > 0 {
		sendSections(assertions, oldToken, sender, s)
		log.Info("Finished handling query by sending assertion from cache", "query", q,
			"answer", assertions)
		return
	}

	//negative answer lookup (note that it can occur a positive answer if assertion removed from cache)
	sections := negativeCacheLookup(q, sender, oldToken, s)
	if len(sections) > 0 {
		//TODO CFE For each type check if one of the zone or shards contain the queried
		//assertion. If there is at least one assertion answer with it. If no assertion is
		//contained in a zone or shard for any of the queried connection, answer with the shortest
		//element. shortest according to what? size in bytes? how to efficiently determine that.
		//e.g. using gob encoding. alternatively we could also count the number of contained
		//elements.
		sendSection(sections[0], oldToken, sender, s)
		trace(oldToken, fmt.Sprintf("found negative assertion matching query: %v", sections[0]))
		log.Info("Finished handling query by sending shard or zone from cache", "query", q)
		return
	}

	log.Debug("No entry found in negAssertion cache directly matching the query")
	log.Debug("Put query on pending query cache")
	tok := oldToken
	if !q.ContainsOption(query.QOTokenTracing) {
		tok = token.New()
	}
	validUntil := time.Now().Add(s.config.QueryValidity).Unix() //Upper bound for forwarded query expiration time
	if q.Expiration < validUntil {
		validUntil = q.Expiration
	}
	isNew := s.caches.PendingQueries.Add(msgSectionSender{Section: q, Sender: sender, Token: oldToken})
	log.Info("Added query into to pending query cache", "info",
		msgSectionSender{Section: q, Sender: sender, Token: oldToken}, "newToken", tok)
	if isNew {
		recResolverAddr := connection.Info{
			Type:     connection.Chan,
			ChanAddr: connection.ChannelAddr{ID: "-" + s.inputChannel.RemoteAddr().String()},
		}
		if s.caches.PendingQueries.AddToken(tok, validUntil, recResolverAddr, q.Name, q.Context, q.Types) {
			newQuery := &query.Name{
				Name:       q.Name,
				Context:    q.Context,
				Expiration: validUntil,
				Types:      q.Types,
			}
			log.Debug("Forward query to recursive resolver")
			s.sendToRecursiveResolver(message.Message{Token: tok, Content: []section.Section{newQuery}})
		} //else answer already arrived and callback function has already been invoked
	} else {
		log.Info("Query already sent.")
	}
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
