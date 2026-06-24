package redback

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/vendors"
)

func TestNewContextName_RoundTrip(t *testing.T) {
	attr := NewContextName("subscriber-vrf")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeContextName, vtype)
	assert.Equal(t, "subscriber-vrf", string(val))
}

func TestNew_ExplicitType(t *testing.T) {
	attr := New(VendorTypeSessionTimeoutAction, []byte{0x01})
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeSessionTimeoutAction, vtype)
	assert.Equal(t, []byte{0x01}, val)
}

func TestDecode_NonRedbackRejected(t *testing.T) {
	ciscoAttr := vendors.NewVSA(9, 1, []byte("x"))
	_, _, ok := Decode(ciscoAttr)
	assert.False(t, ok)
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(2352), VendorID)
}
