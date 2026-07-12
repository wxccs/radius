// Package huawei implements Vendor-Specific attributes for Huawei
// (SMI Network Management Private Enterprise Code 2011).
//
// Huawei RADIUS extension attributes are carried inside the standard
// RFC 2865 §5.26 Vendor-Specific attribute (Type 26) with the Vendor-Id
// set to 2011. This code originated with 3Com and was carried by the
// early 3Com/H3C lineage; Huawei retains it to this day. H3C
// Technologies Co., Limited has since registered its own SMI code
// (25506) - see the h3c sub-package - so Vendor-Id 2011 now uniquely
// identifies Huawei VSAs on the wire.
//
// The sub-attribute numbers and semantics below follow the Huawei
// "S1700, S5700, S6700 V600R025C00" product documentation, table
// "华为RADIUS扩展属性" (Huawei RADIUS Extension Attributes).
package huawei

import (
	"encoding/binary"
	"net"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Huawei's SMI Network Management Private Enterprise Code.
// Huawei shares code 2011 with H3C / 3Com for historical reasons; see
// the package documentation for the implication.
const VendorID uint32 = 2011

// Huawei VSA sub-type numbers, per the Huawei RADIUS Extension
// Attributes table. Sub-types are encoded as the vendor-type byte inside
// the Type 26 VSA; the "26-N" notation in the documentation means
// Type-26 VSA with vendor sub-type N.
const (
	// VendorTypeInputPeakInformationRate is the
	// HW-Input-Peak-Information-Rate VSA (4-byte integer, bit/s). Peak
	// information rate of traffic from the user to the NAS.
	VendorTypeInputPeakInformationRate byte = 1
	// VendorTypeInputCommittedInformationRate is the
	// HW-Input-Committed-Information-Rate VSA (4-byte integer, bit/s).
	// Committed information rate of upstream traffic.
	VendorTypeInputCommittedInformationRate byte = 2
	// VendorTypeInputCommittedBurstSize is the
	// HW-Input-Committed-Burst-Size VSA (4-byte integer, bit).
	// Committed burst size of upstream traffic.
	VendorTypeInputCommittedBurstSize byte = 3
	// VendorTypeOutputPeakInformationRate is the
	// HW-Output-Peak-Information-Rate VSA (4-byte integer, bit/s). Peak
	// information rate of traffic from the NAS to the user.
	VendorTypeOutputPeakInformationRate byte = 4
	// VendorTypeOutputCommittedInformationRate is the
	// HW-Output-Committed-Information-Rate VSA (4-byte integer, bit/s).
	// Committed information rate of downstream traffic.
	VendorTypeOutputCommittedInformationRate byte = 5
	// VendorTypeOutputCommittedBurstSize is the
	// HW-Output-Committed-Burst-Size VSA (4-byte integer, bit).
	// Committed burst size of downstream traffic.
	VendorTypeOutputCommittedBurstSize byte = 6

	// VendorTypeUserNameAccessLimit is the HW-UserName-Access-Limit VSA
	// (4-byte integer). Maximum number of users allowed to access under
	// one user name. Access-Accept only.
	VendorTypeUserNameAccessLimit byte = 18
	// VendorTypeConnectID is the HW-Connect-ID VSA (4-byte integer).
	// Index of the user connection.
	VendorTypeConnectID byte = 26
	// VendorTypeFTPDirectory is the HW-FTP-Directory VSA (string).
	// Initial directory for FTP users.
	VendorTypeFTPDirectory byte = 28
	// VendorTypeExecPrivilege is the HW-Exec-Privilege VSA (4-byte
	// integer). Privilege level of an administrative user, valid range
	// 0-3; values >= 4 are invalid.
	VendorTypeExecPrivilege byte = 29
	// VendorTypeQoSData is the HW-Qos-Data VSA (string). QoS template
	// name (max 64 bytes) used to configure traffic policing.
	VendorTypeQoSData byte = 31
	// VendorTypeVoiceVLAN is the HW-VoiceVlan VSA (4-byte integer).
	// Voice VLAN authorization marker; 1 marks the authorized VLAN as a
	// Voice VLAN.
	VendorTypeVoiceVLAN byte = 33
	// VendorTypeNASStartupTimeStamp is the HW-NAS-Startup-Time-Stamp VSA
	// (4-byte integer). NAS boot time in seconds since the Unix epoch.
	VendorTypeNASStartupTimeStamp byte = 59
	// VendorTypeIPHostAddress is the HW-IP-Host-Address VSA (string).
	// User IP and MAC, format "A.B.C.D hh:hh:hh:hh:hh:hh".
	VendorTypeIPHostAddress byte = 60
	// VendorTypeUpPriority is the HW-Up-Priority VSA (4-byte integer).
	// 802.1p priority of upstream user traffic.
	VendorTypeUpPriority byte = 61
	// VendorTypeDownPriority is the HW-Down-Priority VSA (4-byte
	// integer). 802.1p priority of downstream user traffic.
	VendorTypeDownPriority byte = 62
	// VendorTypeDataFilter is the HW-Data-Filter VSA (string). ACL
	// rules the RADIUS server pushes down to the user (DACL). A packet
	// may carry multiple instances.
	VendorTypeDataFilter byte = 82
	// VendorTypeDomainName is the HW-Domain-Name VSA (string). Name of
	// the domain the user actually belongs to (may be a forced domain).
	VendorTypeDomainName byte = 138
	// VendorTypeAPInformation is the HW-AP-Information VSA (string).
	// MAC of the AP for a wireless user, format H-H-H.
	VendorTypeAPInformation byte = 141
	// VendorTypeUserInformation is the HW-User-Information VSA
	// (string). Security-check control information the RADIUS server
	// pushes to EAPoL users.
	VendorTypeUserInformation byte = 142
	// VendorTypeUserPolicy is the HW-User-Policy VSA (string). Name of
	// the service profile carrying the user's authorization and policy.
	VendorTypeUserPolicy byte = 146
	// VendorTypeAccessType is the HW-Access-Type VSA (4-byte integer).
	// User access type in authentication/accounting requests: 1 Dot1x,
	// 2 MAC auth, 3 Portal, 6 management user.
	VendorTypeAccessType byte = 153
	// VendorTypePortalURL is the HW-Portal-URL VSA (string). Forced
	// redirect URL (max 247 bytes).
	VendorTypePortalURL byte = 156
	// VendorTypeDHCPOption is the HW-DHCP-Option VSA (string). DHCP
	// Option information in TLV format (max 247 bytes). A packet may
	// carry multiple instances.
	VendorTypeDHCPOption byte = 158
	// VendorTypeUCLGroup is the HW-UCL-Group VSA (4-byte integer).
	// UCL group index.
	VendorTypeUCLGroup byte = 160
	// VendorTypeLLDP is the HW-LLDP VSA (string). LLDP information
	// (max 247 bytes). A packet may carry multiple instances.
	VendorTypeLLDP byte = 163
	// VendorTypeMDN is the HW-MDN VSA (string). MDN information
	// (max 247 bytes). A packet may carry multiple instances.
	VendorTypeMDN byte = 164
	// VendorTypeAcctIPv6InputOctets is the HW-Acct-ipv6-Input-Octets
	// VSA (4-byte integer). Upstream IPv6 traffic byte count.
	VendorTypeAcctIPv6InputOctets byte = 166
	// VendorTypeAcctIPv6OutputOctets is the HW-Acct-ipv6-Output-Octets
	// VSA (4-byte integer). Downstream IPv6 traffic byte count.
	VendorTypeAcctIPv6OutputOctets byte = 167
	// VendorTypeAcctIPv6InputPackets is the HW-Acct-ipv6-Input-Packets
	// VSA (4-byte integer). Upstream IPv6 packet count.
	VendorTypeAcctIPv6InputPackets byte = 168
	// VendorTypeAcctIPv6OutputPackets is the
	// HW-Acct-ipv6-Output-Packets VSA (4-byte integer). Downstream
	// IPv6 packet count.
	VendorTypeAcctIPv6OutputPackets byte = 169
	// VendorTypeAcctIPv6InputGigawords is the
	// HW-Acct-ipv6-Input-Gigawords VSA (4-byte integer). Number of
	// 4 GB multiples of upstream IPv6 bytes; combined with
	// HW-Acct-ipv6-Input-Octets gives the full upstream IPv6 byte count.
	VendorTypeAcctIPv6InputGigawords byte = 170
	// VendorTypeAcctIPv6OutputGigawords is the
	// HW-Acct-ipv6-Output-Gigawords VSA (4-byte integer). Number of
	// 4 GB multiples of downstream IPv6 bytes; combined with
	// HW-Acct-ipv6-Output-Octets gives the full downstream IPv6 byte
	// count.
	VendorTypeAcctIPv6OutputGigawords byte = 171
	// VendorTypeRedirectACL is the HW-Redirect-ACL VSA (string).
	// Redirect IPv4 ACL number/name; only matched users are redirected.
	VendorTypeRedirectACL byte = 173
	// VendorTypeIPv6RedirectACL is the HW-IPv6-Redirect-ACL VSA
	// (string). Redirect IPv6 ACL number/name.
	VendorTypeIPv6RedirectACL byte = 178
	// VendorTypeMACsecPolicy is the HW-MACsec-Policy VSA (string).
	// Authorized MACsec policy: "must-secure" or "should-secure".
	VendorTypeMACsecPolicy byte = 180
	// VendorTypeAVPair is the HW-AVPair VSA (string). An
	// "attribute=value" pair; the extensible sub-attribute framework.
	// Length 1-247. Wireless users only.
	VendorTypeAVPair byte = 188
	// VendorTypeMUDURL is the HW-MUD-URL VSA (string). Identity
	// specification (MUD) URL of an iConnect terminal, carried in
	// authentication requests.
	VendorTypeMUDURL byte = 202
	// VendorTypeVIPLevelID is the HW-VIP-Level-ID VSA (4-byte
	// integer). User priority, range 0-1; higher is higher priority.
	// Wireless users only.
	VendorTypeVIPLevelID byte = 203
	// VendorTypeExtSpecific is the HW-Ext-Specific VSA (string).
	// User extension attributes (user-dscp-in/out, user-command,
	// user-ops, supplicant-mode, ...).
	VendorTypeExtSpecific byte = 238
	// VendorTypeUserAccessInfo is the HW-User-Access-Info VSA
	// (string). User access information.
	VendorTypeUserAccessInfo byte = 239
	// VendorTypeAccessDeviceInfo is the HW-Access-Device-Info VSA
	// (string). Access device information.
	VendorTypeAccessDeviceInfo byte = 240
	// VendorTypeReachableDetect is the HW-Reachable-Detect VSA
	// (string). Reachability detection information.
	VendorTypeReachableDetect byte = 244
	// VendorTypeIPv6FilterID is the HW-IPv6-Filter-ID VSA (string).
	// IPv6 ACL number/name authorized by the RADIUS server.
	VendorTypeIPv6FilterID byte = 251
	// VendorTypeFramedIPv6Address is the HW-Framed-IPv6-Address VSA
	// (16-byte IPv6 address). The user's IPv6 address.
	VendorTypeFramedIPv6Address byte = 253
	// VendorTypeVersion is the HW-Version VSA (string). Device version
	// information.
	VendorTypeVersion byte = 254
	// VendorTypeProductID is the HW-Product-ID VSA (string). Device
	// product ID.
	VendorTypeProductID byte = 255
)

// newIntVSA is an unexported helper that encodes a 4-byte big-endian
// integer value into a Huawei VSA of the given sub-type. It mirrors the
// RADIUS integer format used by packet.NewInteger.
func newIntVSA(vt byte, n uint32) packet.Attribute {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return vendors.NewVSA(VendorID, vt, b)
}

// newStrVSA is an unexported helper that wraps a UTF-8 string into a
// Huawei VSA of the given sub-type.
func newStrVSA(vt byte, s string) packet.Attribute {
	return vendors.NewVSA(VendorID, vt, []byte(s))
}

// New constructs a Huawei VSA with an explicit vendor-type and value.
// Use this for sub-types that do not have a dedicated constructor.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// NewInputPeakInformationRate constructs a HW-Input-Peak-Information-Rate
// VSA. rate is the peak upstream rate in bit/s.
func NewInputPeakInformationRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputPeakInformationRate, rate)
}

// NewInputCommittedInformationRate constructs a
// HW-Input-Committed-Information-Rate VSA. rate is the committed
// upstream rate in bit/s.
func NewInputCommittedInformationRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputCommittedInformationRate, rate)
}

// NewInputCommittedBurstSize constructs a
// HW-Input-Committed-Burst-Size VSA. size is the committed upstream
// burst size in bits.
func NewInputCommittedBurstSize(size uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputCommittedBurstSize, size)
}

// NewOutputPeakInformationRate constructs a
// HW-Output-Peak-Information-Rate VSA. rate is the peak downstream rate
// in bit/s.
func NewOutputPeakInformationRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputPeakInformationRate, rate)
}

// NewOutputCommittedInformationRate constructs a
// HW-Output-Committed-Information-Rate VSA. rate is the committed
// downstream rate in bit/s.
func NewOutputCommittedInformationRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputCommittedInformationRate, rate)
}

// NewOutputCommittedBurstSize constructs a
// HW-Output-Committed-Burst-Size VSA. size is the committed downstream
// burst size in bits.
func NewOutputCommittedBurstSize(size uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputCommittedBurstSize, size)
}

// NewUserNameAccessLimit constructs a HW-UserName-Access-Limit VSA. n
// is the per-user-name access limit (0 forbids, 0xFFFFFFFF means
// unlimited).
func NewUserNameAccessLimit(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeUserNameAccessLimit, n)
}

// NewConnectID constructs a HW-Connect-ID VSA.
func NewConnectID(id uint32) packet.Attribute {
	return newIntVSA(VendorTypeConnectID, id)
}

// NewFTPDirectory constructs a HW-FTP-Directory VSA.
func NewFTPDirectory(dir string) packet.Attribute {
	return newStrVSA(VendorTypeFTPDirectory, dir)
}

// NewExecPrivilege constructs a HW-Exec-Privilege VSA. level is the
// administrative user privilege level; valid range is 0-3.
func NewExecPrivilege(level uint32) packet.Attribute {
	return newIntVSA(VendorTypeExecPrivilege, level)
}

// NewQoSData constructs a HW-Qos-Data VSA. name is the QoS template
// name (max 64 bytes).
func NewQoSData(name string) packet.Attribute {
	return newStrVSA(VendorTypeQoSData, name)
}

// NewVoiceVLAN constructs a HW-VoiceVlan VSA. marker is the Voice VLAN
// authorization marker (1 marks a Voice VLAN).
func NewVoiceVLAN(marker uint32) packet.Attribute {
	return newIntVSA(VendorTypeVoiceVLAN, marker)
}

// NewNASStartupTimeStamp constructs a HW-NAS-Startup-Time-Stamp VSA.
// ts is the NAS boot time in seconds since the Unix epoch.
func NewNASStartupTimeStamp(ts uint32) packet.Attribute {
	return newIntVSA(VendorTypeNASStartupTimeStamp, ts)
}

// NewIPHostAddress constructs a HW-IP-Host-Address VSA. addr should be
// in the "A.B.C.D hh:hh:hh:hh:hh:hh" form; it is carried verbatim.
func NewIPHostAddress(addr string) packet.Attribute {
	return newStrVSA(VendorTypeIPHostAddress, addr)
}

// NewUpPriority constructs a HW-Up-Priority VSA. p is the 802.1p
// priority of upstream user traffic.
func NewUpPriority(p uint32) packet.Attribute {
	return newIntVSA(VendorTypeUpPriority, p)
}

// NewDownPriority constructs a HW-Down-Priority VSA. p is the 802.1p
// priority of downstream user traffic.
func NewDownPriority(p uint32) packet.Attribute {
	return newIntVSA(VendorTypeDownPriority, p)
}

// NewDataFilter constructs a HW-Data-Filter VSA. rules is the ACL rule
// string (DACL) pushed by the RADIUS server.
func NewDataFilter(rules string) packet.Attribute {
	return newStrVSA(VendorTypeDataFilter, rules)
}

// NewDomainName constructs a HW-Domain-Name VSA.
func NewDomainName(name string) packet.Attribute {
	return newStrVSA(VendorTypeDomainName, name)
}

// NewAPInformation constructs a HW-AP-Information VSA. mac is the AP
// MAC in H-H-H form; carried verbatim.
func NewAPInformation(mac string) packet.Attribute {
	return newStrVSA(VendorTypeAPInformation, mac)
}

// NewUserInformation constructs a HW-User-Information VSA.
func NewUserInformation(info string) packet.Attribute {
	return newStrVSA(VendorTypeUserInformation, info)
}

// NewUserPolicy constructs a HW-User-Policy VSA. name is the service
// profile name.
func NewUserPolicy(name string) packet.Attribute {
	return newStrVSA(VendorTypeUserPolicy, name)
}

// NewAccessType constructs a HW-Access-Type VSA. t is the user access
// type (1 Dot1x, 2 MAC auth, 3 Portal, 6 management user).
func NewAccessType(t uint32) packet.Attribute {
	return newIntVSA(VendorTypeAccessType, t)
}

// NewPortalURL constructs a HW-Portal-URL VSA. url is the forced
// redirect URL (max 247 bytes).
func NewPortalURL(url string) packet.Attribute {
	return newStrVSA(VendorTypePortalURL, url)
}

// NewDHCPOption constructs a HW-DHCP-Option VSA. opt is the DHCP Option
// information in TLV format (max 247 bytes).
func NewDHCPOption(opt string) packet.Attribute {
	return newStrVSA(VendorTypeDHCPOption, opt)
}

// NewUCLGroup constructs a HW-UCL-Group VSA. idx is the UCL group index.
func NewUCLGroup(idx uint32) packet.Attribute {
	return newIntVSA(VendorTypeUCLGroup, idx)
}

// NewLLDP constructs a HW-LLDP VSA. info is the LLDP information
// (max 247 bytes).
func NewLLDP(info string) packet.Attribute {
	return newStrVSA(VendorTypeLLDP, info)
}

// NewMDN constructs a HW-MDN VSA. info is the MDN information
// (max 247 bytes).
func NewMDN(info string) packet.Attribute {
	return newStrVSA(VendorTypeMDN, info)
}

// NewAcctIPv6InputOctets constructs a HW-Acct-ipv6-Input-Octets VSA. n
// is the upstream IPv6 byte count.
func NewAcctIPv6InputOctets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeAcctIPv6InputOctets, n)
}

// NewAcctIPv6OutputOctets constructs a HW-Acct-ipv6-Output-Octets VSA.
// n is the downstream IPv6 byte count.
func NewAcctIPv6OutputOctets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeAcctIPv6OutputOctets, n)
}

// NewAcctIPv6InputPackets constructs a HW-Acct-ipv6-Input-Packets VSA.
// n is the upstream IPv6 packet count.
func NewAcctIPv6InputPackets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeAcctIPv6InputPackets, n)
}

// NewAcctIPv6OutputPackets constructs a HW-Acct-ipv6-Output-Packets VSA.
// n is the downstream IPv6 packet count.
func NewAcctIPv6OutputPackets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeAcctIPv6OutputPackets, n)
}

// NewAcctIPv6InputGigawords constructs a HW-Acct-ipv6-Input-Gigawords
// VSA. n is the number of 4 GB multiples of upstream IPv6 bytes.
func NewAcctIPv6InputGigawords(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeAcctIPv6InputGigawords, n)
}

// NewAcctIPv6OutputGigawords constructs a
// HW-Acct-ipv6-Output-Gigawords VSA. n is the number of 4 GB multiples
// of downstream IPv6 bytes.
func NewAcctIPv6OutputGigawords(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeAcctIPv6OutputGigawords, n)
}

// NewRedirectACL constructs a HW-Redirect-ACL VSA. acl is the redirect
// IPv4 ACL number/name.
func NewRedirectACL(acl string) packet.Attribute {
	return newStrVSA(VendorTypeRedirectACL, acl)
}

// NewIPv6RedirectACL constructs a HW-IPv6-Redirect-ACL VSA. acl is the
// redirect IPv6 ACL number/name.
func NewIPv6RedirectACL(acl string) packet.Attribute {
	return newStrVSA(VendorTypeIPv6RedirectACL, acl)
}

// NewMACsecPolicy constructs a HW-MACsec-Policy VSA. policy is the
// authorized MACsec policy ("must-secure" or "should-secure"); carried
// verbatim and not validated.
func NewMACsecPolicy(policy string) packet.Attribute {
	return newStrVSA(VendorTypeMACsecPolicy, policy)
}

// NewAVPair constructs a HW-AVPair VSA. avpair is an "attribute=value"
// string (length 1-247). Wireless users only.
func NewAVPair(avpair string) packet.Attribute {
	return newStrVSA(VendorTypeAVPair, avpair)
}

// NewMUDURL constructs a HW-MUD-URL VSA. url is the MUD identity
// specification URL.
func NewMUDURL(url string) packet.Attribute {
	return newStrVSA(VendorTypeMUDURL, url)
}

// NewVIPLevelID constructs a HW-VIP-Level-ID VSA. level is the user
// priority (range 0-1). Wireless users only.
func NewVIPLevelID(level uint32) packet.Attribute {
	return newIntVSA(VendorTypeVIPLevelID, level)
}

// NewExtSpecific constructs a HW-Ext-Specific VSA. val is the user
// extension attribute string (e.g. "user-dscp-in=46").
func NewExtSpecific(val string) packet.Attribute {
	return newStrVSA(VendorTypeExtSpecific, val)
}

// NewUserAccessInfo constructs a HW-User-Access-Info VSA.
func NewUserAccessInfo(info string) packet.Attribute {
	return newStrVSA(VendorTypeUserAccessInfo, info)
}

// NewAccessDeviceInfo constructs a HW-Access-Device-Info VSA.
func NewAccessDeviceInfo(info string) packet.Attribute {
	return newStrVSA(VendorTypeAccessDeviceInfo, info)
}

// NewReachableDetect constructs a HW-Reachable-Detect VSA.
func NewReachableDetect(info string) packet.Attribute {
	return newStrVSA(VendorTypeReachableDetect, info)
}

// NewIPv6FilterID constructs a HW-IPv6-Filter-ID VSA. acl is the IPv6
// ACL number/name authorized by the RADIUS server.
func NewIPv6FilterID(acl string) packet.Attribute {
	return newStrVSA(VendorTypeIPv6FilterID, acl)
}

// NewFramedIPv6Address constructs a HW-Framed-IPv6-Address VSA. ip is
// encoded as a 16-byte IPv6 address; if ip is not a valid IPv6 address,
// 16 zero bytes are stored.
func NewFramedIPv6Address(ip net.IP) packet.Attribute {
	v6 := ip.To16()
	if v6 == nil {
		v6 = make([]byte, 16)
	}
	return vendors.NewVSA(VendorID, VendorTypeFramedIPv6Address, append([]byte(nil), v6...))
}

// NewVersion constructs a HW-Version VSA.
func NewVersion(ver string) packet.Attribute {
	return newStrVSA(VendorTypeVersion, ver)
}

// NewProductID constructs a HW-Product-ID VSA.
func NewProductID(id string) packet.Attribute {
	return newStrVSA(VendorTypeProductID, id)
}

// Decode returns the vendor-type and value if attr is a Huawei VSA
// (Vendor-Id 2011). Returns ok=false otherwise.
//
// Vendor-Id 2011 uniquely identifies Huawei on the wire: H3C now uses
// its own code 25506 (see the h3c sub-package), so a 2011 VSA is a
// Huawei VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
