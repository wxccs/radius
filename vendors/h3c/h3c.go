// Package h3c implements Vendor-Specific attributes for H3C
// (Hangzhou H3C Technologies / New H3C Technologies), which inherited
// the 3Com SMI Network Management Private Enterprise Code 2011.
//
// H3C VSAs use the standard RFC 2865 §5.26 layout. The most common
// H3C VSA sub-types carry user-group, access-level, and NAS-specific
// configuration strings.
package h3c

import (
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is H3C / 3Com's SMI Network Management Private Enterprise
// Code, as registered with IANA.
const VendorID uint32 = 2011

// H3C VSA sub-type numbers commonly seen in H3C NAS deployments.
const (
	// VendorTypeInputPeakRate is the Input-Peak-Rate VSA (bytes/s).
	VendorTypeInputPeakRate byte = 1
	// VendorTypeInputAverageRate is the Input-Average-Rate VSA.
	VendorTypeInputAverageRate byte = 2
	// VendorTypeOutputPeakRate is the Output-Peak-Rate VSA.
	VendorTypeOutputPeakRate byte = 3
	// VendorTypeOutputAverageRate is the Output-Average-Rate VSA.
	VendorTypeOutputAverageRate byte = 4
	// VendorTypeUserGroup is the User-Group name VSA, carrying a
	// UTF-8 string identifying the H3C user group for the session.
	VendorTypeUserGroup byte = 5
	// VendorTypeAccessLevel is the Access-Level VSA (integer 0..3).
	VendorTypeAccessLevel byte = 6
)

// New constructs an H3C VSA with an explicit vendor-type and value.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// NewUserGroup constructs an H3C User-Group VSA.
func NewUserGroup(group string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeUserGroup, []byte(group))
}

// Decode returns the vendor-type and value if attr is an H3C VSA.
// Returns ok=false if attr is not an H3C VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
