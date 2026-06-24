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

package packet

import (
	"net"
	"testing"

	"github.com/wxccs/radius/types"
)

// benchPacket is a representative Access-Request with a mix of string,
// integer, IP, and octets attributes. Marshal/Unmarshal benchmarks use it
// to cover the common codec paths.
func benchPacket() *Packet {
	return &Packet{
		Code:       types.AccessRequest,
		Identifier: 42,
		Authenticator: [16]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		},
		Attributes: []Attribute{
			NewString(types.AttrUserName, "benchmark-user"),
			NewString(types.AttrUserPassword, "benchmark-password"),
			NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 0, 0, 1)),
			NewInteger(types.AttrNASPort, 42),
			NewInteger(types.AttrServiceType, 2),
			NewString(types.AttrNASIdentifier, "bench-nas-01"),
			NewOctets(types.AttrState, []byte("session-state-token")),
		},
	}
}

func BenchmarkPacket_Marshal(b *testing.B) {
	pkt := benchPacket()
	secret := []byte("bench-secret")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := pkt.Marshal(secret); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPacket_Unmarshal(b *testing.B) {
	pkt := benchPacket()
	secret := []byte("bench-secret")
	raw, err := pkt.Marshal(secret)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var p Packet
		if err := p.Unmarshal(raw, secret); err != nil {
			b.Fatal(err)
		}
	}
}
