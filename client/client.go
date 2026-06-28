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

// Package client provides ready-to-use RADIUS clients built on top of the
// transport and protocol packages.
//
// The protocol.Client is transport-agnostic; callers must inject a
// transport that satisfies protocol.Transport (transport.UDPClient and
// transport.TCPClient both do). This package removes that wiring burden
// with two constructors:
//
//   - NewUDPClient dials a UDP socket to a server and wraps a protocol.Client
//     around it. Retransmission is enabled by default (RFC 2865 §2.5).
//   - NewTCPClient dials a single TCP connection to a server and wraps a
//     protocol.Client around it. Retransmission is disabled by default
//     (RFC 6613 §2.6.1).
//
// Both constructors accept functional options for timeout, retransmission
// policy, logging, and per-protocol-family secret selection.
package client

import (
	"net"
	"time"

	radiuslog "github.com/wxccs/radius/v2/log"
	"github.com/wxccs/radius/v2/protocol"
	"github.com/wxccs/radius/v2/transport"
)

// Config controls the behavior of a constructed Client. Zero values fall
// back to sensible defaults documented per-field.
type Config struct {
	// Network selects "udp" / "udp4" / "udp6" for UDP clients, or
	// "tcp" / "tcp4" / "tcp6" for TCP clients. Defaults to "udp4" or
	// "tcp4" respectively when empty.
	Network string

	// Timeout is the default per-exchange deadline applied to every
	// Authenticate / Account / SendCoA / SendDisconnect call when the
	// caller does not supply its own context deadline. Zero disables
	// the default deadline (calls block until the server replies or the
	// retransmission policy is exhausted).
	Timeout time.Duration

	// Retransmit governs UDP retransmission. When zero a default policy
	// of 3 attempts with 2s/16s backoff is used. Ignored for TCP clients
	// (always single-attempt per RFC 6613 §2.6.1).
	Retransmit protocol.RetransmitPolicy

	// Logger injected into the underlying protocol.Client. nil falls
	// back to log.Default (NopLogger unless the application called
	// log.SetDefault).
	Logger radiuslog.Logger
}

// UDPClient is a protocol.Client configured to exchange packets with a
// single RADIUS server over UDP. The underlying transport.UDPClient is
// exposed via Transport for advanced callers that need to send raw bytes.
type UDPClient struct {
	*protocol.Client
	transport *transport.UDPClient
	cfg       Config
}

// NewUDPClient dials a UDP socket to server and returns a Client ready
// for Authenticate / Account / SendCoA / SendDisconnect calls.
//
// secret is the RADIUS shared secret used for authenticator computation
// and User-Password encryption. It MUST NOT be empty.
func NewUDPClient(server *net.UDPAddr, secret []byte, cfg Config) (*UDPClient, error) {
	network := cfg.Network
	if network == "" {
		network = "udp4"
	}
	tr, err := transport.DialUDP(network, server, nil)
	if err != nil {
		return nil, err
	}
	opts := []protocol.Option{
		protocol.WithRetransmitPolicy(cfg.retransmitOrZero()),
		protocol.WithDefaultTimeout(cfg.Timeout),
	}
	if cfg.Logger != nil {
		opts = append(opts, protocol.WithLogger(cfg.Logger))
	}
	return &UDPClient{
		Client:    protocol.NewClient(tr, secret, opts...),
		transport: tr,
		cfg:       cfg,
	}, nil
}

// Transport returns the underlying UDP transport.
func (c *UDPClient) Transport() *transport.UDPClient { return c.transport }

// Close releases the underlying UDP socket.
func (c *UDPClient) Close() error { return c.transport.Close() }

// TCPClient is a protocol.Client configured to exchange packets with a
// single RADIUS server over TCP (RFC 6613).
type TCPClient struct {
	*protocol.Client
	transport *transport.TCPClient
	cfg       Config
}

// NewTCPClient dials a TCP connection to server and returns a Client ready
// for Authenticate / Account / SendCoA / SendDisconnect calls.
//
// Per RFC 6613 §2.6.1 no retransmission is performed on a TCP connection;
// the Config.Retransmit field is ignored and the client uses a single-attempt
// policy.
func NewTCPClient(server *net.TCPAddr, secret []byte, cfg Config) (*TCPClient, error) {
	network := cfg.Network
	if network == "" {
		network = "tcp4"
	}
	tr, err := transport.DialTCP(network, server)
	if err != nil {
		return nil, err
	}
	opts := []protocol.Option{
		// A single-attempt policy disables retransmission: even though
		// exchangeWithRetransmit still loops, MaxAttempts=1 means only the
		// initial transmission is performed.
		protocol.WithRetransmitPolicy(protocol.RetransmitPolicy{MaxAttempts: 1}),
		protocol.WithDefaultTimeout(cfg.Timeout),
	}
	if cfg.Logger != nil {
		opts = append(opts, protocol.WithLogger(cfg.Logger))
	}
	return &TCPClient{
		Client:    protocol.NewClient(tr, secret, opts...),
		transport: tr,
		cfg:       cfg,
	}, nil
}

// Transport returns the underlying TCP transport.
func (c *TCPClient) Transport() *transport.TCPClient { return c.transport }

// Close releases the underlying TCP connection.
func (c *TCPClient) Close() error { return c.transport.Close() }

// retransmitOrZero returns the configured RetransmitPolicy, or the protocol
// package default when zero.
func (c Config) retransmitOrZero() protocol.RetransmitPolicy {
	// We treat a fully-zero policy as "use default". The protocol package's
	// Attempts() method also falls back to 3 when MaxAttempts <= 0, so a
	// zero Config is functionally equivalent to DefaultRetransmitPolicy.
	if c.Retransmit.MaxAttempts == 0 &&
		c.Retransmit.Initial == 0 &&
		c.Retransmit.Max == 0 &&
		c.Retransmit.Jitter == 0 {
		return protocol.DefaultRetransmitPolicy()
	}
	return c.Retransmit
}
