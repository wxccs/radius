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

// Package types defines RADIUS protocol constants shared across the
// packet, crypto, dictionary, transport, and protocol packages.
//
// All values are derived from the authoritative RFCs:
//   - RFC 2865: RADIUS (base) — Codes 1-3, 11-13, 255; attributes 1-39, 60-63
//   - RFC 2866: RADIUS Accounting — Codes 4-5; attributes 40-51
//   - RFC 2869: RADIUS Extensions — attributes 79-80
//   - RFC 5176: Dynamic Authorization — Codes 43-48
package types

// Code identifies the type of a RADIUS packet. It occupies one octet at the
// start of every packet. See RFC 2865 §3 and RFC 5176 §2.1.
type Code byte

// Packet codes defined by RFC 2865 §3.
const (
	AccessRequest      Code = 1
	AccessAccept       Code = 2
	AccessReject       Code = 3
	AccountingRequest  Code = 4
	AccountingResponse Code = 5
	AccessChallenge    Code = 11
	StatusServer       Code = 12 // experimental
	StatusClient       Code = 13 // experimental
	Reserved           Code = 255
)

// Packet codes defined by RFC 5176 for Change-of-Authorization and
// Disconnect-Message flows. Used in Phase 7.
const (
	CoARequest        Code = 43
	CoAACK            Code = 44
	CoANAK            Code = 45
	DisconnectRequest Code = 46
	DisconnectACK     Code = 47
	DisconnectNAK     Code = 48
)

// IsAccess reports whether c is an authentication-family code
// (Access-Request/Accept/Reject/Challenge).
func (c Code) IsAccess() bool {
	switch c {
	case AccessRequest, AccessAccept, AccessReject, AccessChallenge:
		return true
	}
	return false
}

// IsAccounting reports whether c is an accounting-family code
// (Accounting-Request/Response) as defined by RFC 2866.
func (c Code) IsAccounting() bool {
	return c == AccountingRequest || c == AccountingResponse
}

// IsDynamicAuthorization reports whether c is a CoA or Disconnect code
// as defined by RFC 5176.
func (c Code) IsDynamicAuthorization() bool {
	switch c {
	case CoARequest, CoAACK, CoANAK, DisconnectRequest, DisconnectACK, DisconnectNAK:
		return true
	}
	return false
}

// String returns the canonical name of the code, or "Unknown" if unrecognized.
func (c Code) String() string {
	switch c {
	case AccessRequest:
		return "Access-Request"
	case AccessAccept:
		return "Access-Accept"
	case AccessReject:
		return "Access-Reject"
	case AccountingRequest:
		return "Accounting-Request"
	case AccountingResponse:
		return "Accounting-Response"
	case AccessChallenge:
		return "Access-Challenge"
	case StatusServer:
		return "Status-Server"
	case StatusClient:
		return "Status-Client"
	case CoARequest:
		return "CoA-Request"
	case CoAACK:
		return "CoA-ACK"
	case CoANAK:
		return "CoA-NAK"
	case DisconnectRequest:
		return "Disconnect-Request"
	case DisconnectACK:
		return "Disconnect-ACK"
	case DisconnectNAK:
		return "Disconnect-NAK"
	case Reserved:
		return "Reserved"
	}
	return "Unknown"
}

// Standard attribute type numbers defined by RFC 2865 §5.
// Each constant name uses the RFC attribute name in CamelCase with an Attr prefix.
const (
	AttrUserName               = 1
	AttrUserPassword           = 2
	AttrCHAPPassword           = 3
	AttrNASIPAddress           = 4
	AttrNASPort                = 5
	AttrServiceType            = 6
	AttrFramedProtocol         = 7
	AttrFramedIPAddress        = 8
	AttrFramedIPNetmask        = 9
	AttrFramedRouting          = 10
	AttrFilterID               = 11
	AttrFramedMTU              = 12
	AttrFramedCompression      = 13
	AttrLoginIPHost            = 14
	AttrLoginService           = 15
	AttrLoginTCPPort           = 16
	AttrReplyMessage           = 18
	AttrCallbackNumber         = 19
	AttrCallbackID             = 20
	AttrFramedRoute            = 22
	AttrFramedIPXNetwork       = 23
	AttrState                  = 24
	AttrClass                  = 25
	AttrVendorSpecific         = 26
	AttrSessionTimeout         = 27
	AttrIdleTimeout            = 28
	AttrTerminationAction      = 29
	AttrCalledStationID        = 30
	AttrCallingStationID       = 31
	AttrNASIdentifier          = 32
	AttrProxyState             = 33
	AttrLoginLATService        = 34
	AttrLoginLATNode           = 35
	AttrLoginLATGroup          = 36
	AttrFramedAppleTalkLink    = 37
	AttrFramedAppleTalkNetwork = 38
	AttrFramedAppleTalkZone    = 39
	AttrCHAPChallenge          = 60
	AttrNASPortType            = 61
	AttrPortLimit              = 62
	AttrLoginLATPort           = 63
)

// Accounting attribute type numbers defined by RFC 2866 §5.
const (
	AttrAcctStatusType     = 40
	AttrAcctDelayTime      = 41
	AttrAcctInputOctets    = 42
	AttrAcctOutputOctets   = 43
	AttrAcctSessionID      = 44
	AttrAcctAuthentic      = 45
	AttrAcctSessionTime    = 46
	AttrAcctInputPackets   = 47
	AttrAcctOutputPackets  = 48
	AttrAcctTerminateCause = 49
	AttrAcctMultiSessionID = 50
	AttrAcctLinkCount      = 51
)

// Extension attribute type numbers defined by RFC 2869.
const (
	AttrEAPMessage           = 79
	AttrMessageAuthenticator = 80
	AttrNASPortID            = 87
	AttrAcctInterimInterval  = 85
)

// IPv6 attribute type numbers defined by RFC 3162. Full registration of these
// into the dictionary happens in Phase 4 alongside IPv6 transport support.
const (
	AttrNASIPv6Address    = 95
	AttrFramedInterfaceID = 96
	AttrFramedIPv6Prefix  = 97
	AttrLoginIPv6Host     = 98
	AttrFramedIPv6Route   = 99
	AttrFramedIPv6Pool    = 100
)

// Tunnel attribute type numbers defined by RFC 2868. Registered into the
// dictionary in Phase 6 alongside tunnel-protocol support.
const (
	AttrTunnelType           = 64
	AttrTunnelMediumType     = 65
	AttrTunnelClientEndpoint = 66
	AttrTunnelServerEndpoint = 67
	AttrTunnelPassword       = 69
	AttrTunnelPrivateGroupID = 81
	AttrTunnelAssignmentID   = 82
	AttrTunnelPreference     = 83
	AttrTunnelClientAuthID   = 90
	AttrTunnelServerAuthID   = 91
)

// Error-Cause attribute (RFC 5176 §3.3). Used in CoA/NAK and Disconnect/NAK.
const AttrErrorCause = 101

// Packet and attribute length limits.
//
// RFC 2865 §3: minimum length 20, maximum length 4096.
// RFC 2866 §3: minimum length 20, maximum length 4095 (one less).
// A single attribute occupies 2..255 bytes (Type + Length + Value),
// so Value is at most 253 bytes.
const (
	PacketMinLength        = 20
	PacketMaxLengthRFC2865 = 4096
	PacketMaxLengthRFC2866 = 4095

	AuthenticatorLength = 16

	AttrMinLength      = 2
	AttrMaxLength      = 255
	AttrValueMaxLength = 253

	// UserPasswordMaxLength bounds the cleartext password length before
	// padding to a 16-byte boundary (RFC 2865 §5.2: String is 16..128 octets).
	UserPasswordMaxLength = 128
)

// Well-known UDP ports.
const (
	PortAuth       = 1812
	PortAccounting = 1813
	PortCoA        = 3799
	PortTCP        = 5080 // RFC 6613
)
