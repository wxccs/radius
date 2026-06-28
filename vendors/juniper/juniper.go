// Package juniper implements Vendor-Specific attributes for Juniper
// Networks (SMI Network Management Private Enterprise Code 2636).
//
// Juniper VSAs use the standard RFC 2865 §5.26 layout. The most common
// Juniper VSA sub-types carry session parameters for Juniper's
// JUNOS-branded access devices.
package juniper

import (
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Juniper Networks' SMI Network Management Private
// Enterprise Code, as registered with IANA.
const VendorID uint32 = 2636

// Juniper VSA sub-type numbers commonly seen in Juniper deployments.
const (
	// VendorTypeLocalUserGroup is the Local-User-Group VSA (UTF-8
	// string). Used by JUNOS to assign a user to a local group.
	VendorTypeLocalUserGroup byte = 1
	// VendorTypeAllowCommand is the Allow-Commands-Regexp VSA.
	VendorTypeAllowCommand byte = 2
	// VendorTypeDenyCommand is the Deny-Commands-Regexp VSA.
	VendorTypeDenyCommand byte = 3
	// VendorTypeAllowConfiguration is the Allow-Configuration-Regexp VSA.
	VendorTypeAllowConfiguration byte = 4
	// VendorTypeDenyConfiguration is the Deny-Configuration-Regexp VSA.
	VendorTypeDenyConfiguration byte = 5
)

// New constructs a Juniper VSA with an explicit vendor-type and value.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// NewLocalUserGroup constructs a Juniper Local-User-Group VSA.
func NewLocalUserGroup(group string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeLocalUserGroup, []byte(group))
}

// Decode returns the vendor-type and value if attr is a Juniper VSA.
// Returns ok=false if attr is not a Juniper VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
