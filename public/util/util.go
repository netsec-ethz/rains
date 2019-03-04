package util

import (
	"fmt"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"github.com/scionproto/scion/go/lib/snet"
)

func QueryHostname(name string, addr string) string {
	local, _ := snet.AddrFromString("17-ffaa:1:c2,[127.0.0.1]:0")
	snet.Init(local.IA, "/run/shm/sciond/default.sock", "/run/shm/dispatcher/default.sock")

	types := []object.Type{15}
	opts := []query.Option{}
	token := token.New()
	serverAddr, err := snet.AddrFromString(addr)
	if err != nil {
		fmt.Println(err)
	}

	msg := util.NewQueryMessage(name, ".", time.Now().Add(time.Second).Unix(), types, opts, token)
	reply, err := util.SendQuery(msg, serverAddr, time.Second)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	return zonefile.IO{}.Encode(reply.Content)
}

