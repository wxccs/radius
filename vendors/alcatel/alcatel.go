// Package alcatel implements Vendor-Specific attributes for Alcatel
// (SMI Network Management Private Enterprise Code 800).
//
// Alcatel VSAs use the standard RFC 2865 §5.26 layout. They are most
// often seen in Alcatel-Lucent enterprise and carrier Ethernet gear.
package alcatel

import (
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Alcatel's SMI Network Management Private Enterprise
// Code, as registered with IANA.
const VendorID uint32 = 800

// Alcatel VSA sub-type numbers commonly seen in Alcatel-Lucent
// deployments. The full Alcatel dictionary lists many more; the
// values below are the ones referenced most often.
const (
	// VendorTypeUPGroupID is the User-Profile-Group-ID VSA (integer).
	VendorTypeUPGroupID byte = 1
	// VendorTypeUPClientType is the User-Profile-Client-Type VSA.
	VendorTypeUPClientType byte = 2
	// VendorTypeUPClientMode is the User-Profile-Client-Mode VSA.
	VendorTypeUPClientMode byte = 3
)

// New constructs an Alcatel VSA with an explicit vendor-type and value.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// Decode returns the vendor-type and value if attr is an Alcatel VSA.
// Returns ok=false if attr is not an Alcatel VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
