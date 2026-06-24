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

// Package protocol implements the RADIUS state machines on top of the
// packet and transport layers. It hides wire marshaling and transport
// concerns behind a small Client API:
//
//	Authenticate  — Access-Request / Access-Accept / -Reject / -Challenge
//	Account       — Accounting-Request / Accounting-Response
//	SendCoA       — CoA-Request / CoA-ACK / -NAK
//	SendDisconnect — Disconnect-Request / Disconnect-ACK / -NAK
//
// The Client is safe for concurrent use. Each call acquires an Identifier
// from a per-client pool, marshals the request once, performs the exchange
// with retransmission on UDP, verifies the reply, and releases the
// Identifier.
package protocol

import (
	"context"
	"errors"
	"time"

	radiuslog "github.com/wxccs/radius/log"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/types"
)

// Transport is the interface satisfied by transport.UDPClient and
// transport.TCPClient. The protocol layer is transport-agnostic.
type Transport interface {
	Exchange(ctx context.Context, raw []byte) ([]byte, error)
	Close() error
}

// AuthMethod selects how the Access-Request carries user credentials.
type AuthMethod int

const (
	// AuthPAP places the cleartext password in a User-Password attribute
	// (RFC 2865 §5.2). The packet layer encrypts it using the Request
	// Authenticator.
	AuthPAP AuthMethod = iota
	// AuthEAP signals EAP authentication. The protocol layer prepends a
	// Message-Authenticator attribute to the Access-Request (RFC 2869
	// §5.14) and validates it on every reply.
	AuthEAP
)

// AccessRequest describes an outgoing Access-Request. The Identifier is
// allocated automatically from the Client's pool. If Authenticator is the
// zero value a random one is generated (RFC 2865 §3); otherwise the
// caller-supplied value is used (useful for retransmission scenarios where
// the same Request Authenticator must be replayed across calls).
type AccessRequest struct {
	Authenticator [16]byte
	Attributes    []packet.Attribute
	Method        AuthMethod
}

// AccessResponse holds a parsed Access-Accept / -Reject / -Challenge reply.
type AccessResponse struct {
	Code          types.Code
	Identifier    byte
	Authenticator [16]byte
	Attributes    []packet.Attribute
}

// AccountingRequest describes an outgoing Accounting-Request. The
// Identifier is allocated automatically from the Client's pool.
type AccountingRequest struct {
	Attributes []packet.Attribute
}

// AccountingResponse holds a parsed Accounting-Response reply.
type AccountingResponse struct {
	Code          types.Code
	Identifier    byte
	Authenticator [16]byte
	Attributes    []packet.Attribute
}

// CoARequest describes an outgoing CoA-Request. The Identifier is
// allocated automatically from the Client's pool.
type CoARequest struct {
	Attributes []packet.Attribute
}

// CoAResponse holds a parsed CoA-ACK / CoA-NAK reply.
type CoAResponse struct {
	Code          types.Code
	Identifier    byte
	Authenticator [16]byte
	Attributes    []packet.Attribute
}

// DisconnectRequest describes an outgoing Disconnect-Request. The
// Identifier is allocated automatically from the Client's pool.
type DisconnectRequest struct {
	Attributes []packet.Attribute
}

// DisconnectResponse holds a parsed Disconnect-ACK / Disconnect-NAK reply.
type DisconnectResponse struct {
	Code          types.Code
	Identifier    byte
	Authenticator [16]byte
	Attributes    []packet.Attribute
}

// Client is a high-level RADIUS client. It is safe for concurrent use.
type Client struct {
	transport  Transport
	secret     []byte
	idPool     *IdentifierPool
	retransmit RetransmitPolicy
	log        radiuslog.Logger
}

// Option configures a Client at construction time.
type Option func(*Client)

// WithRetransmitPolicy overrides the default UDP retransmission policy.
func WithRetransmitPolicy(p RetransmitPolicy) Option {
	return func(c *Client) { c.retransmit = p }
}

// WithIdentifierPool overrides the default per-client Identifier pool.
// Useful when multiple clients should share a single pool to coordinate
// Identifier allocation across a single transport.
func WithIdentifierPool(p *IdentifierPool) Option {
	return func(c *Client) { c.idPool = p }
}

// WithLogger overrides the default (Nop) logger.
func WithLogger(l radiuslog.Logger) Option {
	if l == nil {
		return func(c *Client) { c.log = radiuslog.NopLogger{} }
	}
	return func(c *Client) { c.log = l }
}

// NewClient returns a Client that exchanges packets over t using secret.
func NewClient(t Transport, secret []byte, opts ...Option) *Client {
	c := &Client{
		transport:  t,
		secret:     append([]byte(nil), secret...),
		idPool:     NewIdentifierPool(),
		retransmit: DefaultRetransmitPolicy(),
		log:        radiuslog.Default,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Close releases the underlying transport. Safe to call multiple times.
func (c *Client) Close() error {
	return c.transport.Close()
}

// Authenticate sends an Access-Request and waits for one of Access-Accept,
// Access-Reject, or Access-Challenge.
//
// On retransmission the same Identifier and Request Authenticator are
// reused (RFC 2865 §2.5). User-Password attributes (if present) are
// encrypted by the packet layer using the Request Authenticator.
//
// When Method == AuthEAP a Message-Authenticator attribute is added to
// the outgoing request (RFC 2869 §5.14) and verified on the reply.
func (c *Client) Authenticate(ctx context.Context, req *AccessRequest) (*AccessResponse, error) {
	log := c.log.With("func", "protocol.Client.Authenticate")

	allocated, err := c.acquireID(ctx)
	if err != nil {
		return nil, err
	}
	defer c.idPool.Release(allocated)

	auth := req.Authenticator
	if auth == ([16]byte{}) {
		a, err := NewAccessRequestAuthenticator()
		if err != nil {
			return nil, err
		}
		auth = a
	}

	attrs := req.Attributes
	if req.Method == AuthEAP && !containsMessageAuthenticator(attrs) {
		attrs = append([]packet.Attribute{
			packet.NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		}, attrs...)
	}

	pkt := &packet.Packet{
		Code:          types.AccessRequest,
		Identifier:    allocated,
		Authenticator: auth,
		Attributes:    attrs,
	}
	raw, err := pkt.Marshal(c.secret)
	if err != nil {
		log.Error("marshal access-request failed", "error", err)
		return nil, err
	}

	reply, err := c.exchangeWithRetransmit(ctx, raw, allocated, auth, log)
	if err != nil {
		return nil, err
	}
	switch reply.Code {
	case types.AccessAccept, types.AccessReject, types.AccessChallenge:
	default:
		log.Warn("unexpected reply code", "code", reply.Code.String())
		return nil, ErrUnexpectedReply
	}
	return &AccessResponse{
		Code:          reply.Code,
		Identifier:    reply.Identifier,
		Authenticator: reply.Authenticator,
		Attributes:    reply.Attributes,
	}, nil
}

// Account sends an Accounting-Request and waits for an Accounting-Response.
func (c *Client) Account(ctx context.Context, req *AccountingRequest) (*AccountingResponse, error) {
	log := c.log.With("func", "protocol.Client.Account")

	allocated, err := c.acquireID(ctx)
	if err != nil {
		return nil, err
	}
	defer c.idPool.Release(allocated)

	pkt := &packet.Packet{
		Code:       types.AccountingRequest,
		Identifier: allocated,
		Attributes: req.Attributes,
	}
	raw, err := pkt.Marshal(c.secret)
	if err != nil {
		log.Error("marshal accounting-request failed", "error", err)
		return nil, err
	}

	// The Accounting-Request authenticator is computed by packet.Marshal and
	// is not caller-supplied; Unmarshal on the server side will verify it.
	// For reply verification we need the original Request Authenticator,
	// which is bytes 4..20 of the marshaled packet.
	var reqAuth [16]byte
	copy(reqAuth[:], raw[4:20])

	reply, err := c.exchangeWithRetransmit(ctx, raw, allocated, reqAuth, log)
	if err != nil {
		return nil, err
	}
	if reply.Code != types.AccountingResponse {
		log.Warn("unexpected reply code", "code", reply.Code.String())
		return nil, ErrUnexpectedReply
	}
	return &AccountingResponse{
		Code:          reply.Code,
		Identifier:    reply.Identifier,
		Authenticator: reply.Authenticator,
		Attributes:    reply.Attributes,
	}, nil
}

// SendCoA sends a CoA-Request (RFC 5176). A Message-Authenticator attribute
// is added if absent (RFC 5176 §3.4 mandates it).
func (c *Client) SendCoA(ctx context.Context, req *CoARequest) (*CoAResponse, error) {
	log := c.log.With("func", "protocol.Client.SendCoA")

	allocated, err := c.acquireID(ctx)
	if err != nil {
		return nil, err
	}
	defer c.idPool.Release(allocated)

	attrs := req.Attributes
	if !containsMessageAuthenticator(attrs) {
		attrs = append([]packet.Attribute{
			packet.NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		}, attrs...)
	}

	pkt := &packet.Packet{
		Code:       types.CoARequest,
		Identifier: allocated,
		Attributes: attrs,
	}
	raw, err := pkt.Marshal(c.secret)
	if err != nil {
		log.Error("marshal coa-request failed", "error", err)
		return nil, err
	}
	var reqAuth [16]byte
	copy(reqAuth[:], raw[4:20])

	reply, err := c.exchangeWithRetransmit(ctx, raw, allocated, reqAuth, log)
	if err != nil {
		return nil, err
	}
	switch reply.Code {
	case types.CoAACK, types.CoANAK:
	default:
		log.Warn("unexpected reply code", "code", reply.Code.String())
		return nil, ErrUnexpectedReply
	}
	return &CoAResponse{
		Code:          reply.Code,
		Identifier:    reply.Identifier,
		Authenticator: reply.Authenticator,
		Attributes:    reply.Attributes,
	}, nil
}

// SendDisconnect sends a Disconnect-Request (RFC 5176). A Message-Authenticator
// attribute is added if absent (RFC 5176 §3.4 mandates it).
func (c *Client) SendDisconnect(ctx context.Context, req *DisconnectRequest) (*DisconnectResponse, error) {
	log := c.log.With("func", "protocol.Client.SendDisconnect")

	allocated, err := c.acquireID(ctx)
	if err != nil {
		return nil, err
	}
	defer c.idPool.Release(allocated)

	attrs := req.Attributes
	if !containsMessageAuthenticator(attrs) {
		attrs = append([]packet.Attribute{
			packet.NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		}, attrs...)
	}

	pkt := &packet.Packet{
		Code:       types.DisconnectRequest,
		Identifier: allocated,
		Attributes: attrs,
	}
	raw, err := pkt.Marshal(c.secret)
	if err != nil {
		log.Error("marshal disconnect-request failed", "error", err)
		return nil, err
	}
	var reqAuth [16]byte
	copy(reqAuth[:], raw[4:20])

	reply, err := c.exchangeWithRetransmit(ctx, raw, allocated, reqAuth, log)
	if err != nil {
		return nil, err
	}
	switch reply.Code {
	case types.DisconnectACK, types.DisconnectNAK:
	default:
		log.Warn("unexpected reply code", "code", reply.Code.String())
		return nil, ErrUnexpectedReply
	}
	return &DisconnectResponse{
		Code:          reply.Code,
		Identifier:    reply.Identifier,
		Authenticator: reply.Authenticator,
		Attributes:    reply.Attributes,
	}, nil
}

// acquireID returns a freshly allocated Identifier from the pool.
func (c *Client) acquireID(ctx context.Context) (byte, error) {
	return c.idPool.Acquire(ctx)
}

// exchangeWithRetransmit sends raw and waits for a reply. On UDP it
// retransmits the identical bytes per the policy; on TCP the transport
// returns a single attempt result. Replies with mismatched Identifier,
// Response Authenticator, or Message-Authenticator are discarded and
// the loop continues until the context deadline.
//
// On success the reply is returned both as raw bytes and as a parsed
// packet. The parsed packet is already verified by VerifyResponse, so
// callers can trust its Identifier, Authenticator, and Attributes.
func (c *Client) exchangeWithRetransmit(
	ctx context.Context,
	raw []byte,
	expectedID byte,
	requestAuth [16]byte,
	log radiuslog.Logger,
) (*packet.Packet, error) {
	attempts := c.retransmit.Attempts()
	var lastErr error
	for attempt := range attempts {
		if attempt > 0 {
			delay := c.retransmit.NextDelay(attempt - 1)
			log.Info("retransmit", "attempt", attempt, "delay", delay.String())
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		log.Debug("send", "attempt", attempt, "bytes", len(raw))
		reply, err := c.transport.Exchange(ctx, raw)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			lastErr = err
			log.Warn("exchange failed", "attempt", attempt, "error", err)
			continue
		}
		// Verify the reply to decide whether to retransmit. A reply that
		// fails structural parsing or authenticator checks is treated as
		// no reply (RFC 2865 §3 mandates silent discard).
		pkt, vErr := VerifyResponse(reply, expectedID, requestAuth, c.secret)
		if vErr != nil {
			if errors.Is(vErr, ErrIdentifierMismatch) {
				log.Warn("discarding reply with mismatched identifier")
				lastErr = vErr
				continue
			}
			log.Warn("discarding reply failing verification", "error", vErr)
			lastErr = vErr
			continue
		}
		return pkt, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoResponse
}

// containsMessageAuthenticator reports whether attrs already includes a
// Message-Authenticator attribute, so the Client does not add a duplicate.
func containsMessageAuthenticator(attrs []packet.Attribute) bool {
	for _, a := range attrs {
		if a.Type == types.AttrMessageAuthenticator {
			return true
		}
	}
	return false
}
