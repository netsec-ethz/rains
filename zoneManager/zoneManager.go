package main

import (
	"github.com/netsec-ethz/rains/zonepub"
)

func main() {
	//TODO CFE generate zonefile and do sharding according to some configuration
	//TODO CFE handle nextkey-requests
	zonepub.Init("test/rainspub.conf")
}
