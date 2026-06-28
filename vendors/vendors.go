// Package vendors provides shared helpers for constructing and
// decoding Vendor-Specific (Type 26) attributes in the RFC 2865 §5.26
// wire format:
//
//	Vendor-Id (4) | Vendor-Type (1) | Vendor-Length (1) | Vendor-Value (...)
//
// Each vendor lives in its own sub-package (vendors/microsoft,
// vendors/cisco, vendors/h3c, ...) with a VendorID constant and
// convenience constructors for that vendor's commonly used attributes.
// This root package only exposes the shared encoding/decoding glue.
//
// The package name is `vendors` (plural) because Go reserves the
// directory name `vendor/` for vendored module dependencies.
package vendors

import (
	"fmt"

	radiuserrors "github.com/wxccs/radius/v2/errors"
	"github.com/wxccs/radius/v2/packet"
)

// NewVSA constructs a Vendor-Specific attribute for the given vendor.
// vendorType is the vendor's own attribute type number; value is the
// vendor-defined payload. The Vendor-Length field is set to
// 2 + len(value), covering the Vendor-Type and Vendor-Length bytes
// themselves plus the value.
//
// The returned attribute is ready to add to a packet via Packet.Add.
func NewVSA(vendorID uint32, vendorType byte, value []byte) packet.Attribute {
	// RFC 2865 §5.26: the Vendor-Length field must fit in one byte and
	// covers Vendor-Type + Vendor-Length + Vendor-Value. The maximum
	// payload length is therefore 253 bytes (255 - 2).
	if len(value) > 253 {
		value = value[:253]
	}
	payload := make([]byte, 2+len(value))
	payload[0] = vendorType
	payload[1] = byte(2 + len(value))
	copy(payload[2:], value)
	return packet.NewVendorSpecific(vendorID, payload)
}

// DecodeVSA extracts the vendor-type and vendor-value from a Type 26
// attribute. Returns:
//
//   - vendorID: the 4-byte Vendor-Id from the attribute Value
//   - vendorType: the 1-byte vendor-specific type
//   - value: a copy of the vendor-defined payload (Vendor-Length - 2 bytes)
//   - ErrInvalidAttribute if attr is not a Type 26 attribute or its
//     Value is too short to contain the Vendor-Type/Vendor-Length header.
//
// The Vendor-Length field is checked against the actual payload length
// to detect truncated attributes; a mismatch is reported as
// ErrInvalidAttribute.
func DecodeVSA(attr packet.Attribute) (vendorID uint32, vendorType byte, value []byte, err error) {
	rawVendorID, payload, err := attr.VendorSpecific()
	if err != nil {
		return 0, 0, nil, fmt.Errorf("radius: decode VSA: %w", err)
	}
	if len(payload) < 2 {
		return rawVendorID, 0, nil, fmt.Errorf(
			"%w: VSA payload too short (%d bytes, need at least 2)",
			radiuserrors.ErrInvalidAttribute, len(payload))
	}
	vendorType = payload[0]
	declaredLen := int(payload[1])
	// declaredLen covers Vendor-Type(1) + Vendor-Length(1) + Vendor-Value.
	// So the value portion is declaredLen - 2 bytes, and it must fit
	// within the remaining payload.
	if declaredLen < 2 {
		return rawVendorID, vendorType, nil, fmt.Errorf(
			"%w: VSA Vendor-Length %d is too small",
			radiuserrors.ErrInvalidAttribute, declaredLen)
	}
	wantValueLen := declaredLen - 2
	if len(payload)-2 < wantValueLen {
		return rawVendorID, vendorType, nil, fmt.Errorf(
			"%w: VSA declares %d value bytes but only %d are present",
			radiuserrors.ErrInvalidAttribute, wantValueLen, len(payload)-2)
	}
	// Return a copy so callers cannot mutate the attribute's internal
	// buffer through the returned slice.
	value = append([]byte(nil), payload[2:2+wantValueLen]...)
	return rawVendorID, vendorType, value, nil
}

// MatchVSA returns the vendor-type and value if attr is a VSA whose
// Vendor-Id matches vendorID. Returns ok=false for any other case
// (non-VSA attribute, wrong Vendor-Id, malformed VSA payload).
//
// Convenience wrapper for vendor sub-packages that want to filter on
// their own VendorID without repeating the error handling.
func MatchVSA(attr packet.Attribute, vendorID uint32) (vendorType byte, value []byte, ok bool) {
	vid, vt, val, err := DecodeVSA(attr)
	if err != nil {
		return 0, nil, false
	}
	if vid != vendorID {
		return 0, nil, false
	}
	return vt, val, true
}
