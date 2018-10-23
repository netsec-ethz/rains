package generate

import (
	"time"
)

type Delay struct {
	ZoneIPToContinent map[string]int
	ZoneIPToTLD       map[string]int
	RootIPAddr        string
}

func (d *Delay) Calc(continent, tld int, dstIP string) time.Duration {
	if d.RootIPAddr == dstIP {
		return time.Millisecond
	} else if d.ZoneIPToContinent[dstIP] != continent {
		return 200 * time.Millisecond
	} else if d.ZoneIPToTLD[dstIP] != tld {
		return 40 * time.Millisecond
	}
	return time.Millisecond
}
