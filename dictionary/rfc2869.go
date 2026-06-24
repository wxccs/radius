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

	"github.com/wxccs/radius/types"
)

// registerRFC2869 registers extension attributes from RFC 2869. This covers
// the ARAP family (70-74), prompt/password-retry helpers (75-78), the EAP
// pair (79-80), and the accounting/session helpers (85, 87, 88).
//
// Message-Authenticator (80) is a 16-byte HMAC-MD5; we mark it TypeOctets
// since the packet layer treats it as opaque binary and computes the HMAC
// itself. EAP-Message (79) carries EAP packet octets and may be fragmented
// across multiple attributes, so TypeOctets applies as well.
func registerRFC2869() {
	defs := []AttributeDef{
		{Type: types.AttrARAPPassword, Name: "ARAP-Password", ValueType: TypeOctets},
		{Type: types.AttrARAPFeatures, Name: "ARAP-Features", ValueType: TypeOctets},
		{Type: types.AttrARAPZoneAccess, Name: "ARAP-Zone-Access", ValueType: TypeInteger},
		{Type: types.AttrARAPSecurity, Name: "ARAP-Security", ValueType: TypeInteger},
		{Type: types.AttrARAPSecurityData, Name: "ARAP-Security-Data", ValueType: TypeOctets},
		{Type: types.AttrPasswordRetry, Name: "Password-Retry", ValueType: TypeInteger},
		{Type: types.AttrPrompt, Name: "Prompt", ValueType: TypeInteger},
		{Type: types.AttrConnectInfo, Name: "Connect-Info", ValueType: TypeString},
		{Type: types.AttrConfigurationToken, Name: "Configuration-Token", ValueType: TypeString},
		{Type: types.AttrEAPMessage, Name: "EAP-Message", ValueType: TypeOctets},
		{Type: types.AttrMessageAuthenticator, Name: "Message-Authenticator", ValueType: TypeOctets},
		{Type: types.AttrAcctInterimInterval, Name: "Acct-Interim-Interval", ValueType: TypeInteger},
		{Type: types.AttrNASPortID, Name: "NAS-Port-Id", ValueType: TypeString},
		{Type: types.AttrFramedPool, Name: "Framed-Pool", ValueType: TypeString},
	}
	for _, def := range defs {
		if err := defaultDict.Register(def); err != nil {
			panic(errors.New("dictionary: failed to register RFC 2869 attribute " + def.Name))
		}
	}
}
