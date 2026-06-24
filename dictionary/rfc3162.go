// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 wxccs
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

	"github.com/wxccs/radius/types"
)

// registerRFC3162 registers IPv6 attributes from RFC 3162. NAS-IPv6-Address
// is a 16-byte IPv6 address; Framed-Interface-ID is an 8-byte interface
// identifier; Framed-IPv6-Prefix carries a prefix-length + address pair and
// is treated here as opaque octets (the prefix encoding is handled by the
// packet layer when needed). Login-IPv6-Host and Framed-IPv6-Pool mirror
// their IPv4 counterparts.
func registerRFC3162() {
	defs := []AttributeDef{
		{Type: types.AttrNASIPv6Address, Name: "NAS-IPv6-Address", ValueType: TypeIPv6Addr},
		{Type: types.AttrFramedInterfaceID, Name: "Framed-Interface-Id", ValueType: TypeOctets},
		{Type: types.AttrFramedIPv6Prefix, Name: "Framed-IPv6-Prefix", ValueType: TypeOctets},
		{Type: types.AttrLoginIPv6Host, Name: "Login-IPv6-Host", ValueType: TypeIPv6Addr},
		{Type: types.AttrFramedIPv6Route, Name: "Framed-IPv6-Route", ValueType: TypeString},
		{Type: types.AttrFramedIPv6Pool, Name: "Framed-IPv6-Pool", ValueType: TypeString},
	}
	for _, def := range defs {
		if err := defaultDict.Register(def); err != nil {
			panic(errors.New("dictionary: failed to register RFC 3162 attribute " + def.Name))
		}
	}
}
