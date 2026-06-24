package protocol

import (
	"net"

	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/types"
)

// AccessRequestBuilder fluently constructs an *AccessRequest. The zero value
// is not usable; obtain one via NewAccessRequest.
type AccessRequestBuilder struct {
	req *AccessRequest
}

// NewAccessRequest returns a builder seeded with Method=AuthPAP and an empty
// Attributes slice.
func NewAccessRequest() *AccessRequestBuilder {
	return &AccessRequestBuilder{req: &AccessRequest{Method: AuthPAP}}
}

// PAP sets Method=AuthPAP and appends User-Name and User-Password attributes.
// The password is encrypted at marshal time using the Request Authenticator
// and the shared secret.
func (b *AccessRequestBuilder) PAP(user, password string) *AccessRequestBuilder {
	b.req.Method = AuthPAP
	b.req.Attributes = append(b.req.Attributes,
		packet.NewString(types.AttrUserName, user),
		packet.NewString(types.AttrUserPassword, password),
	)
	return b
}

// EAP switches the request to EAP mode. The protocol layer prepends a
// Message-Authenticator attribute at marshal time when one is not already
// present.
func (b *AccessRequestBuilder) EAP() *AccessRequestBuilder {
	b.req.Method = AuthEAP
	return b
}

// Method sets the AuthMethod explicitly. Prefer PAP/EAP for readability.
func (b *AccessRequestBuilder) Method(m AuthMethod) *AccessRequestBuilder {
	b.req.Method = m
	return b
}

// Authenticator sets the caller-supplied Request Authenticator. When left as
// the zero value the protocol layer generates a random one per call.
func (b *AccessRequestBuilder) Authenticator(a [16]byte) *AccessRequestBuilder {
	b.req.Authenticator = a
	return b
}

// Attr appends a prebuilt attribute.
func (b *AccessRequestBuilder) Attr(a packet.Attribute) *AccessRequestBuilder {
	b.req.Attributes = append(b.req.Attributes, a)
	return b
}

// AttrString appends a string-valued attribute.
func (b *AccessRequestBuilder) AttrString(t byte, s string) *AccessRequestBuilder {
	return b.Attr(packet.NewString(t, s))
}

// AttrInteger appends a 4-byte big-endian integer attribute.
func (b *AccessRequestBuilder) AttrInteger(t byte, n uint32) *AccessRequestBuilder {
	return b.Attr(packet.NewInteger(t, n))
}

// AttrIP appends a 4-byte IPv4 address attribute.
func (b *AccessRequestBuilder) AttrIP(t byte, ip net.IP) *AccessRequestBuilder {
	return b.Attr(packet.NewIPAddr(t, ip))
}

// AttrIPv6 appends a 16-byte IPv6 address attribute.
func (b *AccessRequestBuilder) AttrIPv6(t byte, ip net.IP) *AccessRequestBuilder {
	return b.Attr(packet.NewIPv6Addr(t, ip))
}

// Attrs replaces the attribute slice with a copy of attrs.
func (b *AccessRequestBuilder) Attrs(attrs []packet.Attribute) *AccessRequestBuilder {
	b.req.Attributes = append([]packet.Attribute(nil), attrs...)
	return b
}

// Build returns the assembled *AccessRequest.
func (b *AccessRequestBuilder) Build() *AccessRequest { return b.req }

// AccountingRequestBuilder fluently constructs an *AccountingRequest.
type AccountingRequestBuilder struct {
	req *AccountingRequest
}

// NewAccountingRequest returns a builder with an empty Attributes slice.
func NewAccountingRequest() *AccountingRequestBuilder {
	return &AccountingRequestBuilder{req: &AccountingRequest{}}
}

// Attr appends a prebuilt attribute.
func (b *AccountingRequestBuilder) Attr(a packet.Attribute) *AccountingRequestBuilder {
	b.req.Attributes = append(b.req.Attributes, a)
	return b
}

// AttrString appends a string-valued attribute.
func (b *AccountingRequestBuilder) AttrString(t byte, s string) *AccountingRequestBuilder {
	return b.Attr(packet.NewString(t, s))
}

// AttrInteger appends a 4-byte big-endian integer attribute.
func (b *AccountingRequestBuilder) AttrInteger(t byte, n uint32) *AccountingRequestBuilder {
	return b.Attr(packet.NewInteger(t, n))
}

// AttrIP appends a 4-byte IPv4 address attribute.
func (b *AccountingRequestBuilder) AttrIP(t byte, ip net.IP) *AccountingRequestBuilder {
	return b.Attr(packet.NewIPAddr(t, ip))
}

// AttrIPv6 appends a 16-byte IPv6 address attribute.
func (b *AccountingRequestBuilder) AttrIPv6(t byte, ip net.IP) *AccountingRequestBuilder {
	return b.Attr(packet.NewIPv6Addr(t, ip))
}

// Attrs replaces the attribute slice with a copy of attrs.
func (b *AccountingRequestBuilder) Attrs(attrs []packet.Attribute) *AccountingRequestBuilder {
	b.req.Attributes = append([]packet.Attribute(nil), attrs...)
	return b
}

// Build returns the assembled *AccountingRequest.
func (b *AccountingRequestBuilder) Build() *AccountingRequest { return b.req }

// CoARequestBuilder fluently constructs a *CoARequest.
type CoARequestBuilder struct {
	req *CoARequest
}

// NewCoARequest returns a builder with an empty Attributes slice.
func NewCoARequest() *CoARequestBuilder {
	return &CoARequestBuilder{req: &CoARequest{}}
}

// Attr appends a prebuilt attribute.
func (b *CoARequestBuilder) Attr(a packet.Attribute) *CoARequestBuilder {
	b.req.Attributes = append(b.req.Attributes, a)
	return b
}

// AttrString appends a string-valued attribute.
func (b *CoARequestBuilder) AttrString(t byte, s string) *CoARequestBuilder {
	return b.Attr(packet.NewString(t, s))
}

// AttrInteger appends a 4-byte big-endian integer attribute.
func (b *CoARequestBuilder) AttrInteger(t byte, n uint32) *CoARequestBuilder {
	return b.Attr(packet.NewInteger(t, n))
}

// AttrIP appends a 4-byte IPv4 address attribute.
func (b *CoARequestBuilder) AttrIP(t byte, ip net.IP) *CoARequestBuilder {
	return b.Attr(packet.NewIPAddr(t, ip))
}

// AttrIPv6 appends a 16-byte IPv6 address attribute.
func (b *CoARequestBuilder) AttrIPv6(t byte, ip net.IP) *CoARequestBuilder {
	return b.Attr(packet.NewIPv6Addr(t, ip))
}

// Attrs replaces the attribute slice with a copy of attrs.
func (b *CoARequestBuilder) Attrs(attrs []packet.Attribute) *CoARequestBuilder {
	b.req.Attributes = append([]packet.Attribute(nil), attrs...)
	return b
}

// Build returns the assembled *CoARequest.
func (b *CoARequestBuilder) Build() *CoARequest { return b.req }

// DisconnectRequestBuilder fluently constructs a *DisconnectRequest.
type DisconnectRequestBuilder struct {
	req *DisconnectRequest
}

// NewDisconnectRequest returns a builder with an empty Attributes slice.
func NewDisconnectRequest() *DisconnectRequestBuilder {
	return &DisconnectRequestBuilder{req: &DisconnectRequest{}}
}

// Attr appends a prebuilt attribute.
func (b *DisconnectRequestBuilder) Attr(a packet.Attribute) *DisconnectRequestBuilder {
	b.req.Attributes = append(b.req.Attributes, a)
	return b
}

// AttrString appends a string-valued attribute.
func (b *DisconnectRequestBuilder) AttrString(t byte, s string) *DisconnectRequestBuilder {
	return b.Attr(packet.NewString(t, s))
}

// AttrInteger appends a 4-byte big-endian integer attribute.
func (b *DisconnectRequestBuilder) AttrInteger(t byte, n uint32) *DisconnectRequestBuilder {
	return b.Attr(packet.NewInteger(t, n))
}

// AttrIP appends a 4-byte IPv4 address attribute.
func (b *DisconnectRequestBuilder) AttrIP(t byte, ip net.IP) *DisconnectRequestBuilder {
	return b.Attr(packet.NewIPAddr(t, ip))
}

// AttrIPv6 appends a 16-byte IPv6 address attribute.
func (b *DisconnectRequestBuilder) AttrIPv6(t byte, ip net.IP) *DisconnectRequestBuilder {
	return b.Attr(packet.NewIPv6Addr(t, ip))
}

// Attrs replaces the attribute slice with a copy of attrs.
func (b *DisconnectRequestBuilder) Attrs(attrs []packet.Attribute) *DisconnectRequestBuilder {
	b.req.Attributes = append([]packet.Attribute(nil), attrs...)
	return b
}

// Build returns the assembled *DisconnectRequest.
func (b *DisconnectRequestBuilder) Build() *DisconnectRequest { return b.req }
