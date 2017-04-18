package zoneFileParser

import (
	"testing"

	log "github.com/inconshreveable/log15"
)

func TestParseZoneFile(t *testing.T) {
	test_zone_1 := `
					:Z: . example.com [
						:S: [
							:A: _smtp._tcp [ :srv: mx 25 10 ]
							:A: foobaz [
								:ip4: 192.0.2.33
								:ip6: 2001:db8:cffe:7ea::33
							]
							:A: quuxnorg [
								:ip4: 192.0.3.33
								:ip6: 2001:db8:cffe:7eb::33
							]
						]
					]
					`
	parser := Parser{}
	assertions, err := parser.ParseZoneFile([]byte(test_zone_1))
	if err != nil {
		log.Warn(err.Error())

	} else {
		for _, a := range assertions {
			log.Info(a.Hash())
		}
	}
}

func TestParseAssertion(t *testing.T) {
	/*test1 := ":A: _smtp._tcp [ :srv: mx 25 10 ]"
	test2 := `:A: foobaz [
								:ip4: 192.0.2.33
								:ip6: 2001:db8:cffe:7ea::33
							]`
	parseAssertion("", "", []byte(test1))
	parseAssertion("", "", []byte(test2))*/
}
