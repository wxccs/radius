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

// Package transport provides UDP (RFC 2865, RFC 3162) and TCP (RFC 6613)
// transports for RADIUS packets.
//
// The package exposes two surfaces:
//
//   - Server side: PacketListener for UDP, TCPListener/TCPConn for TCP.
//   - Client side: UDPClient.Exchange and TCPClient.Exchange for synchronous
//     request/response.
//
// The package does not perform RADIUS-level encoding or authenticator
// verification; callers pass already-marshaled wire bytes in and read wire
// bytes out. Retransmission, Identifier allocation, and duplicate detection
// are deferred to the protocol layer.
//
// Logging is performed through the github.com/wxccs/radius/log interface.
// Every log record carries a `func` attribute whose value is the
// project-root-relative dotted path to the emitting function (e.g.
// "transport.UDPTransport.ReadPacket"). The package does not log shared
// secrets or raw authenticators; trace-level hex dumps, when enabled by the
// caller's logger, zero out the Authenticator and User-Password fields
// before emission.
package transport

import (
	"context"
	"errors"
	"net"
	"os"

	radiuslog "github.com/wxccs/radius/log"
)

// PacketListener receives RADIUS packets from a specific transport (a UDP
// socket on the server side) and writes replies back to the source.
//
// Implementations are safe for concurrent SendPacket calls. A single
// ReadPacket caller is assumed; concurrent readers on the same socket
// are not supported.
type PacketListener interface {
	// ReadPacket reads one complete RADIUS packet from the wire. The
	// returned data is a private copy; callers may retain it without
	// copying. The context's deadline, if any, is applied to the
	// underlying read.
	ReadPacket(ctx context.Context) (data []byte, src net.Addr, err error)

	// SendPacket writes one complete RADIUS packet to dst.
	SendPacket(data []byte, dst net.Addr) error

	// LocalAddr returns the local address the listener is bound to.
	LocalAddr() net.Addr

	// Close releases the underlying socket. Safe for concurrent calls.
	Close() error
}

// withFunc returns a Logger that always includes a `func` attribute set
// to name, per the project's logging convention. name is the project-root-
// relative dotted path to the emitting function (e.g.
// "transport.UDPTransport.ReadPacket"). The underlying Logger is the
// package-level log.Default; applications inject their own logger at
// startup via log.SetDefault.
func withFunc(name string) radiuslog.Logger {
	return radiuslog.Default.With("func", name)
}

// isClosed reports whether err indicates the underlying socket or
// connection has been closed. Matches net.ErrClosed as exposed by the
// standard library since Go 1.16.
func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// isTimeout reports whether err is a deadline-exceeded error from the
// underlying socket or whether ctx is past its deadline. Both signal
// that the operation should be retried at a higher layer (subject to
// the caller's retry policy).
func isTimeout(err error, ctx context.Context) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	return false
}
