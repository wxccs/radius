package cisco

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/vendors"
)

func TestNewAVPair_RoundTrip(t *testing.T) {
	attr := NewAVPair("ip:addr=10.0.0.1")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeAVPair, vtype)
	assert.Equal(t, "ip:addr=10.0.0.1", string(val))
}

func TestNew_ExplicitType(t *testing.T) {
	attr := New(100, []byte{0xAA, 0xBB})
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, byte(100), vtype)
	assert.Equal(t, []byte{0xAA, 0xBB}, val)
}

func TestDecode_NonCiscoRejected(t *testing.T) {
	msAttr := vendors.NewVSA(311, 1, []byte("ms"))
	_, _, ok := Decode(msAttr)
	assert.False(t, ok)
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(9), VendorID)
}
