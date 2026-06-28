// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Daniel Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package dictionary

import (
	"errors"

	"github.com/wxccs/radius/v2/types"
)

// registerRFC2868 registers tunnel attributes from RFC 2868. All tunnel
// attributes carry an optional 1-byte tag (RFC 2868 §3.1) so HasTag is set
// across the board. Tunnel-Password (type 69) additionally uses the RFC 2865
// §5.2 User-Password encryption, so Encrypt=1.
func registerRFC2868() {
	defs := []AttributeDef{
		{Type: types.AttrTunnelType, Name: "Tunnel-Type", ValueType: TypeInteger, HasTag: true},
		{Type: types.AttrTunnelMediumType, Name: "Tunnel-Medium-Type", ValueType: TypeInteger, HasTag: true},
		{Type: types.AttrTunnelClientEndpoint, Name: "Tunnel-Client-Endpoint", ValueType: TypeString, HasTag: true},
		{Type: types.AttrTunnelServerEndpoint, Name: "Tunnel-Server-Endpoint", ValueType: TypeString, HasTag: true},
		{Type: types.AttrTunnelPassword, Name: "Tunnel-Password", ValueType: TypeString, Encrypt: 1, HasTag: true},
		{Type: types.AttrTunnelPrivateGroupID, Name: "Tunnel-Private-Group-Id", ValueType: TypeString, HasTag: true},
		{Type: types.AttrTunnelAssignmentID, Name: "Tunnel-Assignment-Id", ValueType: TypeString, HasTag: true},
		{Type: types.AttrTunnelPreference, Name: "Tunnel-Preference", ValueType: TypeInteger, HasTag: true},
		{Type: types.AttrTunnelClientAuthID, Name: "Tunnel-Client-Auth-Id", ValueType: TypeString, HasTag: true},
		{Type: types.AttrTunnelServerAuthID, Name: "Tunnel-Server-Auth-Id", ValueType: TypeString, HasTag: true},
	}
	for _, def := range defs {
		if err := defaultDict.Register(def); err != nil {
			panic(errors.New("dictionary: failed to register RFC 2868 attribute " + def.Name))
		}
	}
}
