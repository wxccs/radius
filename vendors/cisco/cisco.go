// Package cisco implements Vendor-Specific attributes for Cisco
// Systems (SMI Network Management Private Enterprise Code 9).
//
// Cisco VSAs use the standard RFC 2865 §5.26 layout. The most common
// Cisco VSAs are the "AV-Pair" family — a string of the form
// "attribute=value" carried inside Vendor-Specific sub-type 1.
package cisco

import (
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/vendors"
)

// VendorID is Cisco Systems' SMI Network Management Private Enterprise
// Code, as registered with IANA.
const VendorID uint32 = 9

// Cisco VSA sub-type numbers commonly seen in RADIUS deployments.
// Cisco's official dictionary lists many more; the values below are
// the ones referenced most often in production NAS configurations.
const (
	// VendorTypeAVPair is the generic AV-Pair VSA. Value is a UTF-8
	// string of the form "attribute=value". Multiple AV-Pair VSAs may
	// appear in a single packet.
	VendorTypeAVPair byte = 1
)

// NewAVPair constructs a Cisco AV-Pair VSA. The avpair string should be
// in the "attribute=value" form expected by Cisco NAS; this helper does
// no validation.
func NewAVPair(avpair string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAVPair, []byte(avpair))
}

// New constructs a Cisco VSA with an explicit vendor-type and value.
// Use this for Cisco VSAs that are not AV-Pairs (sub-types other than 1).
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// Decode returns the vendor-type and value if attr is a Cisco VSA.
// Returns ok=false if attr is not a Cisco VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
