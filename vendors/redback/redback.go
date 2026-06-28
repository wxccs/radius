// Package redback implements Vendor-Specific attributes for Redback
// Networks (SMI Network Management Private Enterprise Code 2352),
// now part of Ericsson.
//
// Redback VSAs use the standard RFC 2865 §5.26 layout. They are most
// often seen on SmartEdge-series broadband gateways where they carry
// subscriber profile and QoS parameters.
package redback

import (
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Redback Networks' SMI Network Management Private
// Enterprise Code, as registered with IANA.
const VendorID uint32 = 2352

// Redback VSA sub-type numbers commonly seen in Redback SmartEdge
// deployments.
const (
	// VendorTypeContextName is the Context-Name VSA (UTF-8 string).
	// Identifies the Redback context (VRF) the subscriber belongs to.
	VendorTypeContextName byte = 1
	// VendorTypeLocalAddress is the Local-Address VSA (IPv4).
	VendorTypeLocalAddress byte = 3
	// VendorTypeApplyAccessList is the Apply-Access-List VSA.
	VendorTypeApplyAccessList byte = 4
	// VendorTypeSessionTimeoutAction is the Session-Timeout-Action VSA.
	VendorTypeSessionTimeoutAction byte = 5
)

// New constructs a Redback VSA with an explicit vendor-type and value.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// NewContextName constructs a Redback Context-Name VSA.
func NewContextName(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeContextName, []byte(name))
}

// Decode returns the vendor-type and value if attr is a Redback VSA.
// Returns ok=false if attr is not a Redback VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
