// Package cisco implements Vendor-Specific attributes for Cisco
// Systems (SMI Network Management Private Enterprise Code 9).
//
// Cisco VSAs use the standard RFC 2865 §5.26 layout. The sub-attribute
// numbers and semantics below follow the Cisco IOS 12.2 "Security
// Configuration Guide: RADIUS" appendix "RADIUS Vendor-Specific
// Attributes (VSA)", which groups Cisco VSAs into the AV-Pair, Fax,
// H.323, Large-Scale Dialout, and Miscellaneous families.
//
// The central Cisco VSA is sub-type 1, "cisco-avpair": a UTF-8 string
// of the form "protocol:attribute sep value" (e.g.
// "ip:addr=10.0.0.1", "shell:priv-lvl=15"). Many Cisco authorization
// parameters - callback-dialstring, dial-number, the l2tp-* family,
// min-links, proxyacl#<n>, spi, send-auth, map-class, force-56 - are
// all carried as sub-type 1 AV-Pair values and need no separate
// constructor. The remaining sub-types below are the dedicated VSA
// types used for NAS-Port accounting, store-and-forward fax, and
// H.323/VoIP call accounting.
package cisco

import (
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Cisco Systems' SMI Network Management Private Enterprise
// Code, as registered with IANA.
const VendorID uint32 = 9

// Cisco VSA sub-type numbers, per the Cisco IOS 12.2 RADIUS VSA
// appendix. All carry a UTF-8 string value unless noted.
const (
	// VendorTypeAVPair is the cisco-avpair VSA (sub-type 1). Value is
	// a UTF-8 string of the form "protocol:attribute sep value".
	// Multiple AV-Pair VSAs may appear in a single packet.
	VendorTypeAVPair byte = 1
	// VendorTypeNASPort is the Cisco-NAS-Port VSA (sub-type 2).
	// Additional NAS-Port accounting information as an AV-Pair string.
	VendorTypeNASPort byte = 2

	// --- Store-and-forward fax / e-mail attributes (sub-types 3-21) ---

	// VendorTypeFaxAccountIDOrigin is the Fax-Account-Id-Origin VSA.
	VendorTypeFaxAccountIDOrigin byte = 3
	// VendorTypeFaxMsgID is the Fax-Msg-Id VSA.
	VendorTypeFaxMsgID byte = 4
	// VendorTypeFaxPages is the Fax-Pages VSA.
	VendorTypeFaxPages byte = 5
	// VendorTypeFaxCoverpageFlag is the Fax-Coverpage-Flag VSA.
	VendorTypeFaxCoverpageFlag byte = 6
	// VendorTypeFaxModemTime is the Fax-Modem-Time VSA.
	VendorTypeFaxModemTime byte = 7
	// VendorTypeFaxConnectSpeed is the Fax-Connect-Speed VSA.
	VendorTypeFaxConnectSpeed byte = 8
	// VendorTypeFaxRecipientCount is the Fax-Recipient-Count VSA.
	VendorTypeFaxRecipientCount byte = 9
	// VendorTypeFaxProcessAbortFlag is the Fax-Process-Abort-Flag VSA.
	VendorTypeFaxProcessAbortFlag byte = 10
	// VendorTypeFaxDsnAddress is the Fax-Dsn-Address VSA.
	VendorTypeFaxDsnAddress byte = 11
	// VendorTypeFaxDsnFlag is the Fax-Dsn-Flag VSA.
	VendorTypeFaxDsnFlag byte = 12
	// VendorTypeFaxMdnAddress is the Fax-Mdn-Address VSA.
	VendorTypeFaxMdnAddress byte = 13
	// VendorTypeFaxMdnFlag is the Fax-Mdn-Flag VSA.
	VendorTypeFaxMdnFlag byte = 14
	// VendorTypeFaxAuthStatus is the Fax-Auth-Status VSA.
	VendorTypeFaxAuthStatus byte = 15
	// VendorTypeEmailServerAddress is the Email-Server-Address VSA.
	VendorTypeEmailServerAddress byte = 16
	// VendorTypeEmailServerAckFlag is the Email-Server-Ack-Flag VSA.
	VendorTypeEmailServerAckFlag byte = 17
	// VendorTypeFaxGatewayID is the Gateway-Id VSA (fax family,
	// sub-type 18). Not to be confused with the H.323 Gateway-ID
	// (sub-type 33).
	VendorTypeFaxGatewayID byte = 18
	// VendorTypeFaxCallType is the Call-Type VSA (fax family,
	// sub-type 19). Not to be confused with the H.323 Call-Type
	// (sub-type 27).
	VendorTypeFaxCallType byte = 19
	// VendorTypePortUsed is the Port-Used VSA.
	VendorTypePortUsed byte = 20
	// VendorTypeAbortCause is the Abort-Cause VSA. Indicates the system
	// component that signaled a fax-session abort.
	VendorTypeAbortCause byte = 21

	// --- H.323 / VoIP call-accounting attributes (sub-types 23-31, 33) ---

	// VendorTypeH323RemoteGatewayID is the Remote-Gateway-ID VSA
	// (h323-remote-address). IP address of the remote gateway.
	VendorTypeH323RemoteGatewayID byte = 23
	// VendorTypeH323ConnectionID is the Connection-ID VSA
	// (h323-conf-id). Conference ID.
	VendorTypeH323ConnectionID byte = 24
	// VendorTypeH323SetupTime is the Setup-Time VSA (h323-setup-time).
	// Setup time for the connection in UTC.
	VendorTypeH323SetupTime byte = 25
	// VendorTypeH323CallOrigin is the Call-Origin VSA
	// (h323-call-origin). Origin of the call relative to the gateway
	// (originating / terminating).
	VendorTypeH323CallOrigin byte = 26
	// VendorTypeH323CallType is the Call-Type VSA (h323-call-type).
	// Call leg type (telephony / VoIP).
	VendorTypeH323CallType byte = 27
	// VendorTypeH323ConnectTime is the Connect-Time VSA
	// (h323-connect-time). Connection time for this call leg in UTC.
	VendorTypeH323ConnectTime byte = 28
	// VendorTypeH323DisconnectTime is the Disconnect-Time VSA
	// (h323-disconnect-time). Time this call leg disconnected in UTC.
	VendorTypeH323DisconnectTime byte = 29
	// VendorTypeH323DisconnectCause is the Disconnect-Cause VSA
	// (h323-disconnect-cause). Reason the connection was taken offline
	// per Q.931.
	VendorTypeH323DisconnectCause byte = 30
	// VendorTypeH323VoiceQuality is the Voice-Quality VSA
	// (h323-voice-quality). Impairment factor (ICPIF) for the call.
	VendorTypeH323VoiceQuality byte = 31
	// VendorTypeH323GatewayID is the Gateway-ID VSA (h323-gw-id). Name
	// of the underlying gateway.
	VendorTypeH323GatewayID byte = 33
)

// New constructs a Cisco VSA with an explicit vendor-type and value.
// Use this for sub-types that do not have a dedicated constructor.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// NewAVPair constructs a cisco-avpair VSA (sub-type 1). The avpair
// string should be in the "protocol:attribute sep value" form expected
// by Cisco NAS; this helper does no validation.
func NewAVPair(avpair string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAVPair, []byte(avpair))
}

// NewNASPort constructs a Cisco-NAS-Port VSA (sub-type 2). The value is
// an AV-Pair string carrying additional NAS-Port accounting info.
func NewNASPort(avpair string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeNASPort, []byte(avpair))
}

// NewFaxAccountIDOrigin constructs a Fax-Account-Id-Origin VSA.
func NewFaxAccountIDOrigin(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxAccountIDOrigin, []byte(s))
}

// NewFaxMsgID constructs a Fax-Msg-Id VSA.
func NewFaxMsgID(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxMsgID, []byte(s))
}

// NewFaxPages constructs a Fax-Pages VSA.
func NewFaxPages(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxPages, []byte(s))
}

// NewFaxCoverpageFlag constructs a Fax-Coverpage-Flag VSA.
func NewFaxCoverpageFlag(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxCoverpageFlag, []byte(s))
}

// NewFaxModemTime constructs a Fax-Modem-Time VSA.
func NewFaxModemTime(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxModemTime, []byte(s))
}

// NewFaxConnectSpeed constructs a Fax-Connect-Speed VSA.
func NewFaxConnectSpeed(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxConnectSpeed, []byte(s))
}

// NewFaxRecipientCount constructs a Fax-Recipient-Count VSA.
func NewFaxRecipientCount(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxRecipientCount, []byte(s))
}

// NewFaxProcessAbortFlag constructs a Fax-Process-Abort-Flag VSA.
func NewFaxProcessAbortFlag(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxProcessAbortFlag, []byte(s))
}

// NewFaxDsnAddress constructs a Fax-Dsn-Address VSA.
func NewFaxDsnAddress(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxDsnAddress, []byte(s))
}

// NewFaxDsnFlag constructs a Fax-Dsn-Flag VSA.
func NewFaxDsnFlag(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxDsnFlag, []byte(s))
}

// NewFaxMdnAddress constructs a Fax-Mdn-Address VSA.
func NewFaxMdnAddress(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxMdnAddress, []byte(s))
}

// NewFaxMdnFlag constructs a Fax-Mdn-Flag VSA.
func NewFaxMdnFlag(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxMdnFlag, []byte(s))
}

// NewFaxAuthStatus constructs a Fax-Auth-Status VSA.
func NewFaxAuthStatus(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxAuthStatus, []byte(s))
}

// NewEmailServerAddress constructs an Email-Server-Address VSA.
func NewEmailServerAddress(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeEmailServerAddress, []byte(s))
}

// NewEmailServerAckFlag constructs an Email-Server-Ack-Flag VSA.
func NewEmailServerAckFlag(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeEmailServerAckFlag, []byte(s))
}

// NewFaxGatewayID constructs a Gateway-Id VSA (sub-type 18, fax family).
func NewFaxGatewayID(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxGatewayID, []byte(s))
}

// NewFaxCallType constructs a Call-Type VSA (sub-type 19, fax family).
func NewFaxCallType(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeFaxCallType, []byte(s))
}

// NewPortUsed constructs a Port-Used VSA.
func NewPortUsed(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypePortUsed, []byte(s))
}

// NewAbortCause constructs an Abort-Cause VSA.
func NewAbortCause(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAbortCause, []byte(s))
}

// NewH323RemoteGatewayID constructs a Remote-Gateway-ID VSA
// (h323-remote-address).
func NewH323RemoteGatewayID(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323RemoteGatewayID, []byte(s))
}

// NewH323ConnectionID constructs a Connection-ID VSA (h323-conf-id).
func NewH323ConnectionID(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323ConnectionID, []byte(s))
}

// NewH323SetupTime constructs a Setup-Time VSA (h323-setup-time).
func NewH323SetupTime(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323SetupTime, []byte(s))
}

// NewH323CallOrigin constructs a Call-Origin VSA (h323-call-origin).
func NewH323CallOrigin(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323CallOrigin, []byte(s))
}

// NewH323CallType constructs a Call-Type VSA (h323-call-type).
func NewH323CallType(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323CallType, []byte(s))
}

// NewH323ConnectTime constructs a Connect-Time VSA (h323-connect-time).
func NewH323ConnectTime(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323ConnectTime, []byte(s))
}

// NewH323DisconnectTime constructs a Disconnect-Time VSA
// (h323-disconnect-time).
func NewH323DisconnectTime(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323DisconnectTime, []byte(s))
}

// NewH323DisconnectCause constructs a Disconnect-Cause VSA
// (h323-disconnect-cause).
func NewH323DisconnectCause(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323DisconnectCause, []byte(s))
}

// NewH323VoiceQuality constructs a Voice-Quality VSA
// (h323-voice-quality).
func NewH323VoiceQuality(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323VoiceQuality, []byte(s))
}

// NewH323GatewayID constructs a Gateway-ID VSA (h323-gw-id).
func NewH323GatewayID(s string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeH323GatewayID, []byte(s))
}

// Decode returns the vendor-type and value if attr is a Cisco VSA.
// Returns ok=false if attr is not a Cisco VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
