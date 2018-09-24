package parser

import (
	"fmt"

	"github.com/netsec-ethz/rains/rainslib"

	log "github.com/inconshreveable/log15"
)

func mergeSubjectZone(subject, zone string) string {
	if zone == "." {
		return fmt.Sprintf("%s.", subject)
	}
	if subject == "" {
		return zone
	}
	return fmt.Sprintf("%s.%s", subject, zone)
}

// ValidateZoneRedirects checks that each :redir: in the zone is resolvable.
func ValidateZoneRedirects(in []*rainslib.AssertionSection) error {
	unresolved := make(map[string]string)
	// A concrete assertion is one which resolves to an internet address.
	concreteAssertions := make(map[string]bool)
	for _, as := range in {
		fqdn := mergeSubjectZone(as.SubjectName, as.SubjectZone)
		for _, c := range as.Content {
			if c.Type == rainslib.OTRedirection {
				target := c.Value.(string)
				if _, ok := unresolved[fqdn]; ok {
					return fmt.Errorf("assertion redeclared in zone: %v", fqdn)
				}
				unresolved[fqdn] = target
			}
			if c.Type == rainslib.OTServiceInfo {
				si := c.Value.(rainslib.ServiceInfo)
				if _, ok := unresolved[fqdn]; ok {
					return fmt.Errorf("assertion redeclared in zone: %v", fqdn)
				}
				unresolved[fqdn] = si.Name
			}
			if c.Type == rainslib.OTIP4Addr || c.Type == rainslib.OTIP6Addr {
				concreteAssertions[fqdn] = true
			}
		}
	}
	log.Info("vzr", "unresolved", unresolved, "concrete", concreteAssertions)
	// For each name which is the target of a redirect, check that it can be resolved
	// using the information in this zone alone. We must take special care of the fact
	// that there may be loops.
	for key, _ := range unresolved {
		seen := make(map[string]bool)
		target := key
		for {
			if _, ok := seen[target]; ok {
				return fmt.Errorf("redirect loop for key=%v", key)
			}
			// Target is another redirect.
			if t, ok := unresolved[target]; ok {
				target = t
				seen[key] = true
				continue
			}
			// Target is a concrete assertion.
			if _, ok := concreteAssertions[target]; ok {
				break
			}
			return fmt.Errorf("could not resolve redirect for name: %v", key)
		}
	}
	return nil
}
