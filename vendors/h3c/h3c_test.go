package h3c

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/vendors"
)

func TestNewUserGroup_RoundTrip(t *testing.T) {
	attr := NewUserGroup("engineering")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeUserGroup, vtype)
	assert.Equal(t, "engineering", string(val))
}

func TestNew_ExplicitType(t *testing.T) {
	attr := New(VendorTypeAccessLevel, []byte{0x02})
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeAccessLevel, vtype)
	assert.Equal(t, []byte{0x02}, val)
}

func TestDecode_NonH3CRejected(t *testing.T) {
	ciscoAttr := vendors.NewVSA(9, 1, []byte("x"))
	_, _, ok := Decode(ciscoAttr)
	assert.False(t, ok)
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(2011), VendorID)
}
