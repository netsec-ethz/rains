// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.package main

package scion

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// SetPath is a helper function to set the path on an snet.UDPAddr
func SetPath(addr *snet.UDPAddr, path snet.Path) {
	if path == nil {
		addr.Path = nil
		addr.NextHop = nil
	} else {
		addr.Path = path.Path()
		addr.NextHop = path.OverlayNextHop()
	}
}

// SetDefaultPath sets the first path returned by a query to sciond.
// This is a no-op if if remote is in the local AS.
func SetDefaultPath(addr *snet.UDPAddr) error {
	paths, err := QueryPaths(addr.IA)
	if err != nil || len(paths) == 0 {
		return err
	}
	SetPath(addr, paths[0])
	return nil
}

// QueryPaths queries the DefNetwork's sciond PathQuerier connection for paths to addr
// If addr is in the local IA, an empty slice and no error is returned.
func QueryPaths(ia addr.IA) ([]snet.Path, error) {
	if ia == DefNetwork().IA {
		return nil, nil
	} else {
		paths, err := DefNetwork().PathQuerier.Query(context.Background(), ia)
		if err != nil || len(paths) == 0 {
			return nil, err
		}
		return paths, nil
	}
}
