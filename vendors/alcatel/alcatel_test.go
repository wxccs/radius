package alcatel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/vendors"
)

func TestNew_ExplicitType(t *testing.T) {
	attr := New(VendorTypeUPGroupID, []byte{0x00, 0x00, 0x00, 0x05})
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeUPGroupID, vtype)
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x05}, val)
}

func TestDecode_NonAlcatelRejected(t *testing.T) {
	ciscoAttr := vendors.NewVSA(9, 1, []byte("x"))
	_, _, ok := Decode(ciscoAttr)
	assert.False(t, ok)
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(800), VendorID)
}
