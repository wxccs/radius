// Package paloalto implements Vendor-Specific attributes for Palo Alto
// Networks, Inc. (SMI Network Management Private Enterprise Code 25461).
//
// Palo Alto Networks RADIUS extension attributes are carried inside the
// standard RFC 2865 §5.26 Vendor-Specific attribute (Type 26) with the
// Vendor-Id set to 25461 - the code Palo Alto Networks documents for its
// firewalls and Panorama in the PAN-OS Administrator's Guide, "RADIUS"
// section: "you must specify the vendor code (25461 for Palo Alto
// Networks firewalls or Panorama) and the VSA name and number."
//
// The sub-attribute numbers and semantics below follow the PAN-OS
// Administrator's Guide RADIUS VSA table. The standard RFC 2865 §5.26
// wire layout is used (1-byte Vendor-Type, 1-byte Vendor-Length); the
// guide notes that on a Cisco Secure Access Control Server the Vendor
// Type Field Size and Vendor Length Field Size must both be set to 1,
// which is exactly the layout this package emits via vendors.NewVSA.
//
// All ten sub-attributes are string-valued. Sub-types 6-10 are forwarded
// from GlobalProtect endpoints to the RADIUS server: the PAN-OS guide
// instructs that no value be specified when defining them on the server,
// so they are typically populated by the firewall rather than the server.
package paloalto

import (
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Palo Alto Networks, Inc.'s SMI Network Management
// Private Enterprise Code, as documented by PAN-OS for firewalls and
// Panorama.
const VendorID uint32 = 25461

// PaloAlto VSA sub-type numbers, per the PAN-OS Administrator's Guide
// RADIUS VSA table. Sub-types are encoded as the vendor-type byte inside
// the Type 26 VSA. All are string-valued.
const (
	// VendorTypeAdminRole is the PaloAlto-Admin-Role VSA (string). A
	// default (dynamic) administrative role name or a custom
	// administrative role name on the firewall. Use lower-case for
	// predefined dynamic roles (e.g. "superuser").
	VendorTypeAdminRole byte = 1
	// VendorTypeAdminAccessDomain is the PaloAlto-Admin-Access-Domain VSA
	// (string). The name of an access domain for firewall administrators
	// (Device > Access Domains); define it when the firewall has
	// multiple virtual systems.
	VendorTypeAdminAccessDomain byte = 2
	// VendorTypePanoramaAdminRole is the PaloAlto-Panorama-Admin-Role
	// VSA (string). A default (dynamic) or custom administrative role
	// name on Panorama.
	VendorTypePanoramaAdminRole byte = 3
	// VendorTypePanoramaAdminAccessDomain is the
	// PaloAlto-Panorama-Admin-Access-Domain VSA (string). The name of an
	// access domain for Device Group and Template administrators
	// (Panorama > Access Domains).
	VendorTypePanoramaAdminAccessDomain byte = 4
	// VendorTypeUserGroup is the PaloAlto-User-Group VSA (string). The
	// name of a user group that an authentication profile references.
	VendorTypeUserGroup byte = 5

	// The following sub-types are forwarded from GlobalProtect endpoints
	// to the RADIUS server. The PAN-OS guide states no value should be
	// specified when defining these on the server; they are carried on
	// the wire as strings populated by the firewall.
	// VendorTypeUserDomain is the PaloAlto-User-Domain VSA (string).
	VendorTypeUserDomain byte = 6
	// VendorTypeClientSourceIP is the PaloAlto-Client-Source-IP VSA
	// (string).
	VendorTypeClientSourceIP byte = 7
	// VendorTypeClientOS is the PaloAlto-Client-OS VSA (string).
	VendorTypeClientOS byte = 8
	// VendorTypeClientHostname is the PaloAlto-Client-Hostname VSA
	// (string).
	VendorTypeClientHostname byte = 9
	// VendorTypeGlobalProtectClientVersion is the
	// PaloAlto-GlobalProtect-Client-Version VSA (string).
	VendorTypeGlobalProtectClientVersion byte = 10
)

// newStrVSA is an unexported helper that wraps a UTF-8 string into a
// PaloAlto VSA of the given sub-type.
func newStrVSA(vt byte, s string) packet.Attribute {
	return vendors.NewVSA(VendorID, vt, []byte(s))
}

// New constructs a PaloAlto VSA with an explicit vendor-type and value.
// Use this for sub-types that do not have a dedicated constructor.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// --- Admin account management and authentication VSAs ---

// NewAdminRole constructs a PaloAlto-Admin-Role VSA. role is the
// administrative role name on the firewall; use lower-case for predefined
// dynamic roles (e.g. "superuser").
func NewAdminRole(role string) packet.Attribute {
	return newStrVSA(VendorTypeAdminRole, role)
}

// NewAdminAccessDomain constructs a PaloAlto-Admin-Access-Domain VSA.
// domain is the firewall administrator access domain name.
func NewAdminAccessDomain(domain string) packet.Attribute {
	return newStrVSA(VendorTypeAdminAccessDomain, domain)
}

// NewPanoramaAdminRole constructs a PaloAlto-Panorama-Admin-Role VSA.
// role is the administrative role name on Panorama.
func NewPanoramaAdminRole(role string) packet.Attribute {
	return newStrVSA(VendorTypePanoramaAdminRole, role)
}

// NewPanoramaAdminAccessDomain constructs a
// PaloAlto-Panorama-Admin-Access-Domain VSA. domain is the Device Group
// / Template administrator access domain name.
func NewPanoramaAdminAccessDomain(domain string) packet.Attribute {
	return newStrVSA(VendorTypePanoramaAdminAccessDomain, domain)
}

// NewUserGroup constructs a PaloAlto-User-Group VSA. group is the user
// group name referenced by an authentication profile.
func NewUserGroup(group string) packet.Attribute {
	return newStrVSA(VendorTypeUserGroup, group)
}

// --- VSAs forwarded from GlobalProtect endpoints ---

// NewUserDomain constructs a PaloAlto-User-Domain VSA. Typically
// populated by the firewall from a GlobalProtect endpoint, not set by
// the server.
func NewUserDomain(domain string) packet.Attribute {
	return newStrVSA(VendorTypeUserDomain, domain)
}

// NewClientSourceIP constructs a PaloAlto-Client-Source-IP VSA. The
// value is carried as a string (e.g. an IPv4 address). Typically
// populated by the firewall from a GlobalProtect endpoint.
func NewClientSourceIP(ip string) packet.Attribute {
	return newStrVSA(VendorTypeClientSourceIP, ip)
}

// NewClientOS constructs a PaloAlto-Client-OS VSA. os is the endpoint
// operating system string. Typically populated by the firewall from a
// GlobalProtect endpoint.
func NewClientOS(os string) packet.Attribute {
	return newStrVSA(VendorTypeClientOS, os)
}

// NewClientHostname constructs a PaloAlto-Client-Hostname VSA.
// hostname is the endpoint hostname. Typically populated by the firewall
// from a GlobalProtect endpoint.
func NewClientHostname(hostname string) packet.Attribute {
	return newStrVSA(VendorTypeClientHostname, hostname)
}

// NewGlobalProtectClientVersion constructs a
// PaloAlto-GlobalProtect-Client-Version VSA. version is the GlobalProtect
// client version string. Typically populated by the firewall from a
// GlobalProtect endpoint.
func NewGlobalProtectClientVersion(version string) packet.Attribute {
	return newStrVSA(VendorTypeGlobalProtectClientVersion, version)
}

// Decode returns the vendor-type and value if attr is a PaloAlto VSA
// (Vendor-Id 25461). Returns ok=false otherwise.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
