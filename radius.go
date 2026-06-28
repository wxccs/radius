// Package radius is the top-level entry point for the wxccs/radius library.
// It re-exports the most commonly used symbols from the protocol, packet,
// server, client, and types packages so that applications can use the
// library with a single import:
//
//	c, err := radius.NewUDPClient(addr, secret, radius.Config{Timeout: 5 * time.Second})
//	resp, err := c.Authenticate(ctx, radius.NewAccessRequest().PAP("alice", "pw").Build())
//
// The subpackages remain the source of truth for richer APIs (dictionary,
// crypto, transport, integration helpers). Symbols not re-exported here
// can be reached by importing the corresponding subpackage directly; no
// symbol is hidden — this package only re-exports, never wraps.
package radius

import (
	"github.com/wxccs/radius/v2/client"
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/protocol"
	"github.com/wxccs/radius/v2/server"
	"github.com/wxccs/radius/v2/types"
)

// Code identifies a RADIUS packet code (RFC 2865 §3, RFC 5176 §2.1).
type Code = types.Code

// Packet codes from RFC 2865, RFC 2866, and RFC 5176.
const (
	AccessRequest      = types.AccessRequest
	AccessAccept       = types.AccessAccept
	AccessReject       = types.AccessReject
	AccountingRequest  = types.AccountingRequest
	AccountingResponse = types.AccountingResponse
	AccessChallenge    = types.AccessChallenge
	CoARequest         = types.CoARequest
	CoAACK             = types.CoAACK
	CoANAK             = types.CoANAK
	DisconnectRequest  = types.DisconnectRequest
	DisconnectACK      = types.DisconnectACK
	DisconnectNAK      = types.DisconnectNAK
)

// Commonly-used attribute type numbers from RFC 2865 / 2866 / 2869 / 3162 /
// 5176. The full list lives in the types package.
const (
	AttrUserName             = types.AttrUserName
	AttrUserPassword         = types.AttrUserPassword
	AttrCHAPPassword         = types.AttrCHAPPassword
	AttrNASIPAddress         = types.AttrNASIPAddress
	AttrNASPort              = types.AttrNASPort
	AttrServiceType          = types.AttrServiceType
	AttrFramedIPAddress      = types.AttrFramedIPAddress
	AttrFramedIPNetmask      = types.AttrFramedIPNetmask
	AttrFilterID             = types.AttrFilterID
	AttrReplyMessage         = types.AttrReplyMessage
	AttrState                = types.AttrState
	AttrClass                = types.AttrClass
	AttrVendorSpecific       = types.AttrVendorSpecific
	AttrSessionTimeout       = types.AttrSessionTimeout
	AttrIdleTimeout          = types.AttrIdleTimeout
	AttrCalledStationID      = types.AttrCalledStationID
	AttrCallingStationID     = types.AttrCallingStationID
	AttrNASIdentifier        = types.AttrNASIdentifier
	AttrProxyState           = types.AttrProxyState
	AttrNASPortType          = types.AttrNASPortType
	AttrAcctStatusType       = types.AttrAcctStatusType
	AttrAcctDelayTime        = types.AttrAcctDelayTime
	AttrAcctInputOctets      = types.AttrAcctInputOctets
	AttrAcctOutputOctets     = types.AttrAcctOutputOctets
	AttrAcctSessionID        = types.AttrAcctSessionID
	AttrAcctAuthentic        = types.AttrAcctAuthentic
	AttrAcctSessionTime      = types.AttrAcctSessionTime
	AttrAcctInputPackets     = types.AttrAcctInputPackets
	AttrAcctOutputPackets    = types.AttrAcctOutputPackets
	AttrAcctTerminateCause   = types.AttrAcctTerminateCause
	AttrAcctMultiSessionID   = types.AttrAcctMultiSessionID
	AttrEAPMessage           = types.AttrEAPMessage
	AttrMessageAuthenticator = types.AttrMessageAuthenticator
	AttrNASPortID            = types.AttrNASPortID
	AttrAcctInterimInterval  = types.AttrAcctInterimInterval
	AttrNASIPv6Address       = types.AttrNASIPv6Address
	AttrFramedIPv6Prefix     = types.AttrFramedIPv6Prefix
	AttrFramedIPv6Pool       = types.AttrFramedIPv6Pool
	AttrErrorCause           = types.AttrErrorCause
)

// AuthenticatorLength is the fixed length in bytes of the Request/Response
// Authenticator field.
const AuthenticatorLength = types.AuthenticatorLength

// UDP and TCP ports for RADIUS services (RFC 2865, RFC 2866, RFC 5176,
// RFC 6613).
const (
	PortAuth       = types.PortAuth
	PortAccounting = types.PortAccounting
	PortCoA        = types.PortCoA
	PortTCP        = types.PortTCP
)

// Attribute is a single RADIUS TLV (Type, Length, Value).
type Attribute = packet.Attribute

// Packet is a RADIUS protocol data unit.
type Packet = packet.Packet

// Attribute and packet constructors re-exported from the packet package.
var (
	NewString         = packet.NewString
	NewInteger        = packet.NewInteger
	NewIPAddr         = packet.NewIPAddr
	NewIPv6Addr       = packet.NewIPv6Addr
	NewOctets         = packet.NewOctets
	NewVendorSpecific = packet.NewVendorSpecific
)

// AuthMethod selects how the Access-Request carries user credentials.
type AuthMethod = protocol.AuthMethod

// Authentication methods.
const (
	AuthPAP = protocol.AuthPAP
	AuthEAP = protocol.AuthEAP
)

// Request builders. NewAccessRequest returns a fluent builder whose Build
// method yields a *protocol.AccessRequest suitable for Client.Authenticate.
// The other builders behave analogously for Account, SendCoA, and
// SendDisconnect.
//
// The response struct types (protocol.AccessResponse, protocol.CoAResponse,
// etc.) are intentionally NOT re-exported here: the names AccessRequest,
// AccountingRequest, CoARequest, DisconnectRequest, and AccountingResponse
// refer to the RADIUS packet Code constants from the types package, and Go
// does not permit a type and a const to share a name. Callers receive the
// response via short variable declaration (resp, err := c.Authenticate(...))
// or import the protocol package directly when a named type is required.
var (
	NewAccessRequest     = protocol.NewAccessRequest
	NewAccountingRequest = protocol.NewAccountingRequest
	NewCoARequest        = protocol.NewCoARequest
	NewDisconnectRequest = protocol.NewDisconnectRequest
)

// Builder types re-exported so callers can declare variables of these types.
type (
	AccessRequestBuilder     = protocol.AccessRequestBuilder
	AccountingRequestBuilder = protocol.AccountingRequestBuilder
	CoARequestBuilder        = protocol.CoARequestBuilder
	DisconnectRequestBuilder = protocol.DisconnectRequestBuilder
)

// Client configuration and constructors.
type (
	Config    = client.Config
	UDPClient = client.UDPClient
	TCPClient = client.TCPClient
)

// NewUDPClient dials a UDP socket to a RADIUS server and returns a ready
// Client. NewTCPClient dials a single TCP connection (RFC 6613) instead.
var (
	NewUDPClient = client.NewUDPClient
	NewTCPClient = client.NewTCPClient
)

// Server-side handler types.
type (
	Handler      = server.Handler
	HandlerFunc  = server.HandlerFunc
	Request      = server.Request
	SecretLookup = server.SecretLookup
	UDPServer    = server.UDPServer
	TCPServer    = server.TCPServer
	Mux          = server.Mux
)

// Server constructors and helpers.
var (
	NewUDPServer = server.NewUDPServer
	NewTCPServer = server.NewTCPServer
	StaticSecret = server.StaticSecret
	SecretMap    = server.SecretMap
	NewMux       = server.NewMux
)
