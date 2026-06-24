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

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/wxccs/radius/client"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/protocol"
	"github.com/wxccs/radius/server"
	"github.com/wxccs/radius/types"
)

// BenchmarkUDP_AccessRequestRoundTrip measures the full client→server→client
// path for a single Access-Request/Access-Accept exchange over UDP, including
// marshal, crypto, network I/O, server dispatch, and reply verification.
func BenchmarkUDP_AccessRequestRoundTrip(b *testing.B) {
	ctx := b.Context()

	handler := server.HandlerFunc(func(_ context.Context, req *server.Request) (*packet.Packet, error) {
		return &packet.Packet{
			Code:          types.AccessAccept,
			Identifier:    req.Identifier,
			Authenticator: req.Authenticator,
		}, nil
	})
	srv, err := server.NewUDPServer("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		handler, server.StaticSecret([]byte(testSecret)))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.Serve(ctx) }()

	addr := srv.LocalAddr().(*net.UDPAddr)
	host, portStr, _ := net.SplitHostPort(addr.String())
	port, _ := net.LookupPort("network", portStr)
	c, err := client.NewUDPClient(
		&net.UDPAddr{IP: net.ParseIP(host), Port: port},
		[]byte(testSecret),
		client.Config{Retransmit: protocol.RetransmitPolicy{MaxAttempts: 1}})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	req := &protocol.AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "bench-user"),
			packet.NewString(types.AttrUserPassword, "bench-pass"),
		},
		Method: protocol.AuthPAP,
	}

	b.ResetTimer()
	for b.Loop() {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		resp, err := c.Authenticate(callCtx, req)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
		if resp.Code != types.AccessAccept {
			b.Fatalf("unexpected code %s", resp.Code)
		}
	}
}
