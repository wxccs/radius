package server

import (
	"context"
	"net"
	"strings"

	radiuslog "github.com/wxccs/radius/v2/log"
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
)

// Reply returns a *packet.Packet with the given Code, copying the Request's
// Identifier and Authenticator so the Response Authenticator will be computed
// against the right Request Authenticator when the reply is marshaled.
// Callers add attributes afterwards.
func (req *Request) Reply(code types.Code) *packet.Packet {
	return &packet.Packet{
		Code:          code,
		Identifier:    req.Identifier,
		Authenticator: req.Authenticator,
	}
}

// ReplyWith is Reply plus attribute population. attrs are copied so the
// caller may safely mutate its source slice afterwards.
func (req *Request) ReplyWith(code types.Code, attrs ...packet.Attribute) *packet.Packet {
	p := req.Reply(code)
	p.Attributes = append([]packet.Attribute(nil), attrs...)
	return p
}

// SecretMap returns a SecretLookup backed by a map of client IP strings to
// shared secrets. Keys may be "10.0.0.1" or "10.0.0.1/32"; the prefix is
// stripped and the IP normalized. A missing entry signals "drop the packet"
// (ok=false).
//
// Keys that fail to parse as IPs are kept verbatim and will never match a
// remote IP — register such clients via a custom SecretLookup instead.
func SecretMap(m map[string][]byte) SecretLookup {
	byIP := make(map[string][]byte, len(m))
	for k, v := range m {
		byIP[normalizeIPKey(k)] = v
	}
	return func(remoteIP net.IP) ([]byte, bool) {
		if remoteIP == nil {
			return nil, false
		}
		secret, ok := byIP[remoteIP.String()]
		if !ok {
			return nil, false
		}
		return append([]byte(nil), secret...), true
	}
}

// normalizeIPKey trims whitespace, strips an optional /prefix, and
// canonicalizes the IP via net.ParseIP(...).String() so that "10.0.0.1"
// and "10.0.0.1/32" both map to "10.0.0.1".
func normalizeIPKey(k string) string {
	k = strings.TrimSpace(k)
	if i := strings.IndexByte(k, '/'); i >= 0 {
		k = k[:i]
	}
	if ip := net.ParseIP(k); ip != nil {
		return ip.String()
	}
	return k
}

// Mux is a Handler that dispatches by packet Code.
//
// Unhandled codes fall through to the Fallback handler; when Fallback is nil
// the Mux returns (nil, nil) — silent drop per RFC 2865 §3.
type Mux struct {
	handlers map[types.Code]Handler
	fallback Handler
	log      radiuslog.Logger
}

// NewMux returns an empty Mux.
func NewMux() *Mux {
	return &Mux{
		handlers: make(map[types.Code]Handler),
		log:      radiuslog.Default,
	}
}

// On registers h for the given Code. A later registration for the same
// Code overrides the prior. Returns the Mux for chaining.
func (m *Mux) On(code types.Code, h Handler) *Mux {
	m.handlers[code] = h
	return m
}

// OnFunc is a shortcut for On(code, HandlerFunc(f)).
func (m *Mux) OnFunc(code types.Code, f HandlerFunc) *Mux {
	return m.On(code, f)
}

// Fallback sets the handler invoked for codes without a registered handler.
// Returns the Mux for chaining. A nil Fallback (the default) causes unknown
// codes to be silently dropped.
func (m *Mux) Fallback(h Handler) *Mux {
	m.fallback = h
	return m
}

// Handle implements Handler. It dispatches to the registered handler for
// req.Code, or to the Fallback, or returns (nil, nil) when neither matches.
func (m *Mux) Handle(ctx context.Context, req *Request) (*packet.Packet, error) {
	log := m.log.With("func", "server.Mux.Handle")
	if h, ok := m.handlers[req.Code]; ok {
		return h.Handle(ctx, req)
	}
	if m.fallback != nil {
		return m.fallback.Handle(ctx, req)
	}
	log.Debug("no handler registered for code", "code", req.Code.String())
	return nil, nil
}
