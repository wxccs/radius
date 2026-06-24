package vendors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/types"
)

// TestNewVSA_WireLayout verifies the on-wire VSA layout against
// RFC 2865 §5.26: Vendor-Id(4) | Vendor-Type(1) | Vendor-Length(1) | Value.
func TestNewVSA_WireLayout(t *testing.T) {
	attr := NewVSA(311, 25, []byte{0xAA, 0xBB, 0xCC})
	assert.Equal(t, byte(types.AttrVendorSpecific), attr.Type)

	// Decode via the packet layer to confirm the outer wrapper is right.
	vendorID, payload, err := attr.VendorSpecific()
	require.NoError(t, err)
	assert.Equal(t, uint32(311), vendorID)
	// payload must be Vendor-Type(1) + Vendor-Length(1) + Value(3).
	assert.Equal(t, []byte{25, 5, 0xAA, 0xBB, 0xCC}, payload)
}

func TestNewVSA_ValueOver253IsTruncated(t *testing.T) {
	// The Vendor-Length field covers Vendor-Type + Vendor-Length +
	// Vendor-Value and must fit in one byte. The maximum payload length
	// is therefore 253 bytes; longer values are truncated to fit.
	big := make([]byte, 300)
	for i := range big {
		big[i] = byte(i)
	}
	attr := NewVSA(9, 1, big)
	_, payload, err := attr.VendorSpecific()
	require.NoError(t, err)
	declaredLen := int(payload[1])
	assert.Equal(t, 255, declaredLen, "Vendor-Length must be capped at 255")
	valueLen := declaredLen - 2
	assert.Equal(t, 253, valueLen, "vendor value must be capped at 253 bytes")
}

func TestNewVSA_EmptyValue(t *testing.T) {
	attr := NewVSA(311, 25, nil)
	_, payload, err := attr.VendorSpecific()
	require.NoError(t, err)
	assert.Equal(t, []byte{25, 2}, payload, "empty value yields Vendor-Length=2")
}

func TestDecodeVSA_RoundTrip(t *testing.T) {
	original := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	attr := NewVSA(311, 25, original)

	vid, vtype, val, err := DecodeVSA(attr)
	require.NoError(t, err)
	assert.Equal(t, uint32(311), vid)
	assert.Equal(t, byte(25), vtype)
	assert.Equal(t, original, val)

	// DecodeVSA must return a copy so callers cannot mutate the
	// attribute's internal buffer.
	val[0] = 0xFF
	_, _, val2, err := DecodeVSA(attr)
	require.NoError(t, err)
	assert.Equal(t, original, val2, "decoded value must be a copy")
}

func TestDecodeVSA_NonVSATypeRejected(t *testing.T) {
	attr := packet.NewString(types.AttrUserName, "alice")
	_, _, _, err := DecodeVSA(attr)
	require.ErrorIs(t, err, errors.ErrInvalidAttribute)
}

func TestDecodeVSA_ShortPayloadRejected(t *testing.T) {
	// Vendor-Id only, no Vendor-Type/Vendor-Length.
	attr := packet.NewVendorSpecific(311, []byte{0x00})
	_, _, _, err := DecodeVSA(attr)
	require.ErrorIs(t, err, errors.ErrInvalidAttribute)
}

func TestDecodeVSA_DeclaredLengthTooSmall(t *testing.T) {
	// Vendor-Length=1 (impossibly small; must be at least 2 for the
	// Vendor-Type + Vendor-Length header alone).
	attr := packet.NewVendorSpecific(311, []byte{25, 1, 0xAA})
	_, _, _, err := DecodeVSA(attr)
	require.ErrorIs(t, err, errors.ErrInvalidAttribute)
}

func TestDecodeVSA_TruncatedValueRejected(t *testing.T) {
	// Vendor-Length=5 (claims 3 value bytes) but only 1 byte of value
	// is actually present.
	attr := packet.NewVendorSpecific(311, []byte{25, 5, 0xAA})
	_, _, _, err := DecodeVSA(attr)
	require.ErrorIs(t, err, errors.ErrInvalidAttribute)
}

func TestMatchVSA_MatchingVendor(t *testing.T) {
	attr := NewVSA(311, 25, []byte("mschap2"))
	vt, val, ok := MatchVSA(attr, 311)
	require.True(t, ok)
	assert.Equal(t, byte(25), vt)
	assert.Equal(t, []byte("mschap2"), val)
}

func TestMatchVSA_NonMatchingVendor(t *testing.T) {
	attr := NewVSA(311, 25, []byte("mschap2"))
	_, _, ok := MatchVSA(attr, 9)
	assert.False(t, ok, "Cisco match must fail on Microsoft attribute")
}

func TestMatchVSA_NonVSA(t *testing.T) {
	attr := packet.NewString(types.AttrUserName, "alice")
	_, _, ok := MatchVSA(attr, 311)
	assert.False(t, ok, "match must fail on non-VSA attribute")
}
