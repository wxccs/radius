// This file extends the microsoft package with the Vendor-Specific
// attributes defined by the Microsoft Open Specifications:
//
//   - [MS-RNAP] "Vendor-Specific RADIUS Attributes for Network Access
//     Protection (NAP) Data Structure", v19.0 (2017). Defines 27 VSAs
//     (Vendor-Type 0x22-0x3F), including the Quarantine-*, HCAP-* and
//     AFW-* families that have since been removed from the newer NPAS.
//   - [MS-RNAS] "Vendor-Specific RADIUS Attributes for Network Policy
//     and Access Server Data Structure", v7.0 (2024). Defines 11 VSAs -
//     an evolved subset of MS-RNAP plus the new MS-Azure-Policy-ID (0x41).
//
// Together they cover Vendor-Type 0x22-0x3F and 0x41. The gap at
// 0x26/0x27/0x2B is intentional: those numbers belong to the RFC 2548
// MS-CHAP family declared in microsoft.go. MS-RNAS §2.2.2.1 also defines
// a vendor-specific value for the standard Tunnel-Type (Type 64) attribute
// for SSTP, exposed here as NewTunnelTypeSSTP.
//
// All Microsoft VSAs share Vendor-Id 311 and the RFC 2865 §5.26 layout;
// they decode through the package-level Decode helper in microsoft.go.

package microsoft

import (
	"encoding/binary"
	"net"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
	"github.com/wxccs/radius/v2/vendors"
)

// Microsoft VSA sub-type numbers from MS-RNAP (NAP) and MS-RNAS (NPAS).
// Each constant is annotated with its source: both = present in both
// documents, RNAP = MS-RNAP only (dropped from newer NPAS),
// RNAS = MS-RNAS only.
const (
	// VendorTypeRASClientName is the MS-RAS-Client-Name VSA (both).
	// ASCII null-terminated machine name of the requesting endpoint.
	VendorTypeRASClientName byte = 0x22
	// VendorTypeRASClientVersion is the MS-RAS-Client-Version VSA (both).
	// ASCII version string of the remote access client.
	VendorTypeRASClientVersion byte = 0x23
	// VendorTypeQuarantineIPFilter is the MS-Quarantine-IPFilter VSA
	// (RNAP). IPv4 filter-set list; see NewQuarantineIPFilter.
	VendorTypeQuarantineIPFilter byte = 0x24
	// VendorTypeQuarantineSessionTimeout is the MS-Quarantine-Session-
	// Timeout VSA (RNAP). 32-bit seconds before a restricted connection
	// is disconnected.
	VendorTypeQuarantineSessionTimeout byte = 0x25
	// VendorTypeUserSecurityIdentity is the MS-User-Security-Identity VSA
	// (both). Binary account SID of the requesting user.
	VendorTypeUserSecurityIdentity byte = 0x28
	// VendorTypeIdentityType is the MS-Identity-Type VSA (RNAP).
	// 32-bit value indicating the request is for a machine health check.
	VendorTypeIdentityType byte = 0x29
	// VendorTypeServiceClass is the MS-Service-Class VSA (RNAP). Name of
	// a group of DHCP scopes supplying the endpoint's IP address.
	VendorTypeServiceClass byte = 0x2A
	// VendorTypeQuarantineUserClass is the MS-Quarantine-User-Class VSA
	// (RNAP). DHCP NAP user-class name.
	VendorTypeQuarantineUserClass byte = 0x2C
	// VendorTypeQuarantineState is the MS-Quarantine-State VSA (RNAP).
	// 32-bit enum: full access / restricted / on probation.
	VendorTypeQuarantineState byte = 0x2D
	// VendorTypeQuarantineGraceTime is the MS-Quarantine-Grace-Time VSA
	// (RNAP). 32-bit seconds-since-epoch until access is restricted.
	VendorTypeQuarantineGraceTime byte = 0x2E
	// VendorTypeNetworkAccessServerType is the MS-Network-Access-Server-
	// Type VSA (both). 32-bit enum identifying the NAS type.
	VendorTypeNetworkAccessServerType byte = 0x2F
	// VendorTypeAFWZone is the MS-AFW-Zone VSA (RNAP). 32-bit enum hint
	// for IPsec policy zone selection.
	VendorTypeAFWZone byte = 0x30
	// VendorTypeAFWProtectionLevel is the MS-AFW-Protection-Level VSA
	// (RNAP). 32-bit IPsec protection-level hint.
	VendorTypeAFWProtectionLevel byte = 0x31
	// VendorTypeMachineName is the MS-Machine-Name VSA (both). ANSI
	// octet string naming the requesting endpoint's machine.
	VendorTypeMachineName byte = 0x32
	// VendorTypeIPv6Filter is the MS-IPv6-Filter VSA (both). IPv6 filter
	// set list; structurally identical to MS-Quarantine-IPFilter.
	VendorTypeIPv6Filter byte = 0x33
	// VendorTypeIPv4RemediationServers is the MS-IPv4-Remediation-Servers
	// VSA (RNAP). Reserved byte (0) followed by a list of IPv4 addresses.
	VendorTypeIPv4RemediationServers byte = 0x34
	// VendorTypeIPv6RemediationServers is the MS-IPv6-Remediation-Servers
	// VSA (RNAP). Reserved byte (0) followed by a list of IPv6 addresses.
	VendorTypeIPv6RemediationServers byte = 0x35
	// VendorTypeNotQuarantineCapable is the Not-Quarantine-Capable VSA
	// (RNAP). 32-bit enum: whether the endpoint sent a SoH.
	VendorTypeNotQuarantineCapable byte = 0x36
	// VendorTypeQuarantineSoH is the MS-Quarantine-SoH VSA (RNAP).
	// Statement of Health blob per [TNC-IF-TNCCSPBSoH].
	VendorTypeQuarantineSoH byte = 0x37
	// VendorTypeRASCorrelationID is the MS-RAS-Correlation-ID VSA (both).
	// Curly-braced GUID string for correlating log events.
	VendorTypeRASCorrelationID byte = 0x38
	// VendorTypeExtendedQuarantineState is the MS-Extended-Quarantine-State
	// VSA (RNAP). 32-bit enum with extra restricted-access detail.
	VendorTypeExtendedQuarantineState byte = 0x39
	// VendorTypeHCAPUserGroups is the HCAP-User-Groups VSA (RNAP). ANSI
	// octet string of HCAP user-group names.
	VendorTypeHCAPUserGroups byte = 0x3A
	// VendorTypeHCAPLocationGroupName is the HCAP-Location-Group-Name VSA
	// (RNAP). ANSI octet string of the HCAP location group name.
	VendorTypeHCAPLocationGroupName byte = 0x3B
	// VendorTypeHCAPUserName is the HCAP-User-Name VSA (RNAP). ANSI
	// octet string of the HCAP user name.
	VendorTypeHCAPUserName byte = 0x3C
	// VendorTypeUserIPv4Address is the MS-User-IPv4-Address VSA (both).
	// 32-bit IPv4 address of the requesting endpoint.
	VendorTypeUserIPv4Address byte = 0x3D
	// VendorTypeUserIPv6Address is the MS-User-IPv6-Address VSA (both).
	// 128-bit IPv6 address of the requesting endpoint.
	VendorTypeUserIPv6Address byte = 0x3E
	// VendorTypeRDGDeviceRedirection is the MS-RDG-Device-Redirection VSA
	// (both). 32-bit bitmask controlling Remote Desktop Gateway device
	// redirection.
	VendorTypeRDGDeviceRedirection byte = 0x3F
	// VendorTypeAzurePolicyID is the MS-Azure-Policy-ID VSA (RNAS only).
	// Octet string identifying an Azure Point-to-Site VPN policy.
	VendorTypeAzurePolicyID byte = 0x41
)

// Enumerated values for the 32-bit VSA families, per MS-RNAP §2.2.1.
const (
	// MS-Identity-Type (0x29).
	IdentityTypeMachine uint32 = 0x00000001

	// MS-Quarantine-State (0x2D).
	QuarantineStateFullAccess  uint32 = 0x00000000
	QuarantineStateRestricted  uint32 = 0x00000001
	QuarantineStateOnProbation uint32 = 0x00000002

	// MS-Network-Access-Server-Type (0x2F).
	NASTypeUnspecified           uint32 = 0x00000000
	NASTypeTerminalServerGateway uint32 = 0x00000001
	NASTypeRAS                   uint32 = 0x00000002
	NASTypeDHCP                  uint32 = 0x00000003
	NASTypeHRA                   uint32 = 0x00000005
	NASTypeHCAP                  uint32 = 0x00000006

	// MS-AFW-Zone (0x30).
	AFWZoneEncryptionRequired    uint32 = 0x00000001
	AFWZoneEncryptionNotRequired uint32 = 0x00000002
	AFWZoneEncryptionRequiredAlt uint32 = 0x00000003

	// MS-AFW-Protection-Level (0x31). MS-RNAP does not assign symbolic
	// names to these values; they are exposed as Value1/Value2.
	AFWProtectionLevelValue1 uint32 = 0x00000001
	AFWProtectionLevelValue2 uint32 = 0x00000002

	// Not-Quarantine-Capable (0x36). Note the inverted meaning: 0 means
	// the endpoint DID send a Statement of Health.
	NotQuarantineCapableSoHSent    uint32 = 0x00000000
	NotQuarantineCapableSoHNotSent uint32 = 0x00000001

	// MS-Extended-Quarantine-State (0x39).
	ExtendedQuarantineStateNoData     uint32 = 0x00000000
	ExtendedQuarantineStateTransition uint32 = 0x00000001
	ExtendedQuarantineStateInfected   uint32 = 0x00000002
	ExtendedQuarantineStateUnknown    uint32 = 0x00000003
)

// Bit positions for MS-RDG-Device-Redirection (0x3F). Bit 0 is the least
// significant bit. Setting DisableAll or EnableAll makes bits 0..4 ignored.
const (
	RDGRedirDrives      uint32 = 1 << 0
	RDGRedirPrinters    uint32 = 1 << 1
	RDGRedirSerialPorts uint32 = 1 << 2
	RDGRedirClipboard   uint32 = 1 << 3
	RDGRedirPlugAndPlay uint32 = 1 << 4
	RDGRedirDisableAll  uint32 = 1 << 29
	RDGRedirEnableAll   uint32 = 1 << 30
)

// Tunnel-Type vendor-specific value for SSTP, per MS-RNAS §2.2.2.1.
// Encoded against the standard Tunnel-Type (Type 64) attribute - not a
// VSA - as the Microsoft enterprise ID (0x0137) concatenated with a zero
// tag and value 0x01, yielding 0x00013701 in network byte order.
const TunnelTypeSSTP uint32 = 0x00013701

// Internal constants for assembling MS-Quarantine-IPFilter / MS-IPv6-Filter
// raw values (MS-RNAP §2.2.1.3 / §2.2.1.15). These multi-layer structures
// use little-endian for their header/count fields and network byte order
// for the embedded addresses; callers assemble the raw bytes and pass
// them to NewQuarantineIPFilter / NewIPv6Filter.
const (
	// ForwardAction (within a filter set) and DropAction.
	FilterActionForward uint32 = 0x00000000
	FilterActionDrop    uint32 = 0x00000001

	// FilterSet InfoType values.
	FilterInfoTypeInput      uint32 = 0xFFFF0001
	FilterInfoTypeOutput     uint32 = 0xFFFF0002
	FilterInfoTypeSiteToSite uint32 = 0xFFFF0009

	// LateBound field bitmask (may be OR-combined).
	FilterLateBoundNone               uint32 = 0x00000000
	FilterLateBoundSrcAddrReplaceable uint32 = 0x00000001
	FilterLateBoundDstAddrReplaceable uint32 = 0x00000004
	FilterLateBoundSrcMaskReplaceable uint32 = 0x00000010
	FilterLateBoundDstMaskReplaceable uint32 = 0x00000020

	// Protocol numbers (IANA assigned).
	FilterProtocolAny  uint32 = 0x00000000
	FilterProtocolICMP uint32 = 0x00000001
	FilterProtocolTCP  uint32 = 0x00000006
	FilterProtocolUDP  uint32 = 0x00000011
)

// newUint32VSA wraps a single 32-bit value (network byte order) as a
// Microsoft VSA. Shared by the integer-family constructors below.
func newUint32VSA(vendorType byte, v uint32) packet.Attribute {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return vendors.NewVSA(VendorID, vendorType, b)
}

// ipv4Bytes returns the 4-byte IPv4 representation of ip, or 4 zero
// bytes if ip is not an IPv4 address.
func ipv4Bytes(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...)
	}
	return make([]byte, 4)
}

// ipv6Bytes returns the 16-byte IPv6 representation of ip, or 16 zero
// bytes if ip is not a valid IPv6 address.
func ipv6Bytes(ip net.IP) []byte {
	if v6 := ip.To16(); v6 != nil {
		return append([]byte(nil), v6...)
	}
	return make([]byte, 16)
}

// --- String / ANSI octet-string family ---

// NewRASClientName constructs an MS-RAS-Client-Name VSA. Per MS-RNAP the
// machine name MUST be ASCII and null-terminated, so a trailing NUL byte
// is appended to name.
func NewRASClientName(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeRASClientName, append([]byte(name), 0x00))
}

// NewRASClientVersion constructs an MS-RAS-Client-Version VSA from the
// ASCII version string.
func NewRASClientVersion(version string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeRASClientVersion, []byte(version))
}

// NewServiceClass constructs an MS-Service-Class VSA carrying the DHCP
// scope-group name.
func NewServiceClass(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeServiceClass, []byte(name))
}

// NewQuarantineUserClass constructs an MS-Quarantine-User-Class VSA
// carrying the DHCP NAP user-class name.
func NewQuarantineUserClass(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeQuarantineUserClass, []byte(name))
}

// NewMachineName constructs an MS-Machine-Name VSA carrying the endpoint's
// machine name as an ANSI octet string.
func NewMachineName(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeMachineName, []byte(name))
}

// NewHCAPUserGroups constructs an HCAP-User-Groups VSA.
func NewHCAPUserGroups(groups string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeHCAPUserGroups, []byte(groups))
}

// NewHCAPLocationGroupName constructs an HCAP-Location-Group-Name VSA.
func NewHCAPLocationGroupName(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeHCAPLocationGroupName, []byte(name))
}

// NewHCAPUserName constructs an HCAP-User-Name VSA.
func NewHCAPUserName(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeHCAPUserName, []byte(name))
}

// NewAzurePolicyID constructs an MS-Azure-Policy-ID VSA (MS-RNAS only)
// carrying the Azure Point-to-Site VPN policy identifier.
func NewAzurePolicyID(policyID string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAzurePolicyID, []byte(policyID))
}

// --- 32-bit integer (network byte order) family ---

// NewQuarantineSessionTimeout constructs an MS-Quarantine-Session-Timeout
// VSA. seconds is the time a restricted VPN connection may remain
// restricted before being disconnected.
func NewQuarantineSessionTimeout(seconds uint32) packet.Attribute {
	return newUint32VSA(VendorTypeQuarantineSessionTimeout, seconds)
}

// NewIdentityType constructs an MS-Identity-Type VSA; pass
// IdentityTypeMachine to indicate a machine health-check request.
func NewIdentityType(v uint32) packet.Attribute {
	return newUint32VSA(VendorTypeIdentityType, v)
}

// NewQuarantineState constructs an MS-Quarantine-State VSA; pass one of
// the QuarantineState* constants.
func NewQuarantineState(v uint32) packet.Attribute {
	return newUint32VSA(VendorTypeQuarantineState, v)
}

// NewQuarantineGraceTime constructs an MS-Quarantine-Grace-Time VSA.
// epochSeconds is the seconds-since-1970-UTC deadline after which the
// endpoint is restricted.
func NewQuarantineGraceTime(epochSeconds uint32) packet.Attribute {
	return newUint32VSA(VendorTypeQuarantineGraceTime, epochSeconds)
}

// NewNetworkAccessServerType constructs an MS-Network-Access-Server-Type
// VSA; pass one of the NASType* constants.
func NewNetworkAccessServerType(v uint32) packet.Attribute {
	return newUint32VSA(VendorTypeNetworkAccessServerType, v)
}

// NewAFWZone constructs an MS-AFW-Zone VSA; pass one of the AFWZone*
// constants.
func NewAFWZone(v uint32) packet.Attribute {
	return newUint32VSA(VendorTypeAFWZone, v)
}

// NewAFWProtectionLevel constructs an MS-AFW-Protection-Level VSA.
func NewAFWProtectionLevel(v uint32) packet.Attribute {
	return newUint32VSA(VendorTypeAFWProtectionLevel, v)
}

// NewNotQuarantineCapable constructs a Not-Quarantine-Capable VSA; pass
// NotQuarantineCapableSoHSent or NotQuarantineCapableSoHNotSent.
func NewNotQuarantineCapable(v uint32) packet.Attribute {
	return newUint32VSA(VendorTypeNotQuarantineCapable, v)
}

// NewExtendedQuarantineState constructs an MS-Extended-Quarantine-State
// VSA; pass one of the ExtendedQuarantineState* constants.
func NewExtendedQuarantineState(v uint32) packet.Attribute {
	return newUint32VSA(VendorTypeExtendedQuarantineState, v)
}

// NewRDGDeviceRedirection constructs an MS-RDG-Device-Redirection VSA.
// bits is the OR of the RDGRedir* constants.
func NewRDGDeviceRedirection(bits uint32) packet.Attribute {
	return newUint32VSA(VendorTypeRDGDeviceRedirection, bits)
}

// --- IP address family ---

// NewUserIPv4Address constructs an MS-User-IPv4-Address VSA. If ip is not
// an IPv4 address, 4 zero bytes are stored.
func NewUserIPv4Address(ip net.IP) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeUserIPv4Address, ipv4Bytes(ip))
}

// NewUserIPv6Address constructs an MS-User-IPv6-Address VSA. If ip is not
// a valid IPv6 address, 16 zero bytes are stored.
func NewUserIPv6Address(ip net.IP) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeUserIPv6Address, ipv6Bytes(ip))
}

// --- GUID family ---

// NewRASCorrelationID constructs an MS-RAS-Correlation-ID VSA carrying
// the GUID as its curly-braced string form (e.g.
// "{12345678-1234-1234-1234-123456789abc}"). The string is carried
// verbatim; callers are responsible for supplying the braced form.
func NewRASCorrelationID(guid string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeRASCorrelationID, []byte(guid))
}

// --- Complex binary family ---
//
// MS-Quarantine-IPFilter and MS-IPv6-Filter are multi-layer structures
// (filter-set entries -> filter sets -> filters) that mix little-endian
// header fields with network-order addresses and require 8-byte aligned
// offsets. Full typed builders are out of scope for this update; these
// constructors accept the pre-assembled raw bytes and expose the
// Filter* constants above for callers to assemble them.

// NewQuarantineIPFilter constructs an MS-Quarantine-IPFilter VSA from the
// pre-assembled raw Attribute-Specific Value (IPv4 filters).
func NewQuarantineIPFilter(raw []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeQuarantineIPFilter, append([]byte(nil), raw...))
}

// NewIPv6Filter constructs an MS-IPv6-Filter VSA from the pre-assembled
// raw Attribute-Specific Value (IPv6 filters).
func NewIPv6Filter(raw []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeIPv6Filter, append([]byte(nil), raw...))
}

// NewUserSecurityIdentity constructs an MS-User-Security-Identity VSA
// carrying the binary account SID of the requesting user.
func NewUserSecurityIdentity(sid []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeUserSecurityIdentity, append([]byte(nil), sid...))
}

// NewIPv4RemediationServers constructs an MS-IPv4-Remediation-Servers VSA
// from a list of IPv4 addresses. The value is a reserved byte (0) followed
// by each 4-byte address; non-IPv4 entries contribute 4 zero bytes.
func NewIPv4RemediationServers(ips []net.IP) packet.Attribute {
	buf := make([]byte, 0, 1+4*len(ips))
	buf = append(buf, 0x00) // reserved, MUST be 0
	for _, ip := range ips {
		buf = append(buf, ipv4Bytes(ip)...)
	}
	return vendors.NewVSA(VendorID, VendorTypeIPv4RemediationServers, buf)
}

// NewIPv6RemediationServers constructs an MS-IPv6-Remediation-Servers VSA
// from a list of IPv6 addresses. The value is a reserved byte (0) followed
// by each 16-byte address; invalid entries contribute 16 zero bytes.
func NewIPv6RemediationServers(ips []net.IP) packet.Attribute {
	buf := make([]byte, 0, 1+16*len(ips))
	buf = append(buf, 0x00) // reserved, MUST be 0
	for _, ip := range ips {
		buf = append(buf, ipv6Bytes(ip)...)
	}
	return vendors.NewVSA(VendorID, VendorTypeIPv6RemediationServers, buf)
}

// NewQuarantineSoH constructs an MS-Quarantine-SoH VSA carrying the
// Statement of Health blob ([TNC-IF-TNCCSPBSoH]).
func NewQuarantineSoH(raw []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeQuarantineSoH, append([]byte(nil), raw...))
}

// --- Generic ---

// New constructs a Microsoft VSA with an explicit vendor-type and value.
// Use this for sub-types that do not have a dedicated constructor.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// --- SSTP ---

// NewTunnelTypeSSTP constructs the standard Tunnel-Type (Type 64)
// attribute carrying the Microsoft vendor-specific value for the Secure
// Socket Tunneling Protocol (MS-SSTP), 0x00013701, as defined by
// MS-RNAS §2.2.2.1. Unlike the other constructors in this file, this
// returns a plain RADIUS attribute, not a Vendor-Specific (Type 26) VSA.
func NewTunnelTypeSSTP() packet.Attribute {
	return packet.NewInteger(types.AttrTunnelType, TunnelTypeSSTP)
}
