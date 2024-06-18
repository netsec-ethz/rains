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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// SetDefaultPath sets the first path returned by a query to sciond.
// This is a no-op if if remote is in the local AS.
func SetDefaultPath(addr *snet.UDPAddr) error {
	paths, err := QueryPaths(addr.IA)
	if err != nil {
		return err
	} else if len(paths) > 0 {
		addr.Path = paths[0].Dataplane()
		addr.NextHop = paths[0].UnderlayNextHop()
	} else {
		addr.Path = path.Empty{}
		addr.NextHop = nil
	}
	return nil
}

// QueryPaths queries the DefNetwork's sciond PathQuerier connection for paths to addr
// If addr is in the local IA, an empty slice and no error is returned.
func QueryPaths(ia addr.IA) ([]snet.Path, error) {
	if ia == Host().IA {
		return nil, nil
	} else {
		paths, err := queryPaths(context.TODO(), ia)
		if err != nil || len(paths) == 0 {
			return nil, err
		}
		return paths, nil
	}
}
