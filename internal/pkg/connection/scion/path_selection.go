// Copyright 2018 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/snet"
)

// SetPath is a helper function to set the path on an snet.Addr
func SetPath(addr *snet.Addr, path snet.Path) error {
	if path == nil {
		addr.Path = nil
		addr.NextHop = nil
	} else {
		p := path.Path()
		err := p.InitOffsets()
		if err != nil {
			return err
		}
		addr.Path = p
		addr.NextHop = path.OverlayNextHop()
	}
	return nil
}

// SetDefaultPath sets the first path returned by a query to sciond.
// This is a no-op if if remote is in the local AS.
func SetDefaultPath(addr *snet.Addr) error {
	if addr.IA == DefNetwork().IA {
		_ = SetPath(addr, nil)
	} else {
		paths, err := DefNetwork().PathQuerier.Query(context.Background(), addr.IA)
		if err != nil || len(paths) == 0 {
			return err
		}
		err = SetPath(addr, paths[0])
		if err != nil {
			return err
		}
	}
	return nil
}
