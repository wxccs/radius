package juniper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/vendors"
)

func TestNewLocalUserGroup_RoundTrip(t *testing.T) {
	attr := NewLocalUserGroup("operators")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeLocalUserGroup, vtype)
	assert.Equal(t, "operators", string(val))
}

func TestNew_ExplicitType(t *testing.T) {
	attr := New(VendorTypeAllowCommand, []byte(".*"))
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeAllowCommand, vtype)
	assert.Equal(t, ".*", string(val))
}

func TestDecode_NonJuniperRejected(t *testing.T) {
	msAttr := vendors.NewVSA(311, 1, []byte("x"))
	_, _, ok := Decode(msAttr)
	assert.False(t, ok)
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(2636), VendorID)
}
