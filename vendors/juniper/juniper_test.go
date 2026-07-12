package juniper

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/vendors"
)

func TestNewLocalUserName_RoundTrip(t *testing.T) {
	attr := NewLocalUserName("operators")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeLocalUserName, vtype)
	assert.Equal(t, "operators", string(val))
}

func TestNewAllowCommand_RoundTrip(t *testing.T) {
	attr := NewAllowCommand("(test)|(ping)|(quit)")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeAllowCommand, vtype)
	assert.Equal(t, "(test)|(ping)|(quit)", string(val))
}

func TestNewDenyCommand_RoundTrip(t *testing.T) {
	attr := NewDenyCommand("(request)|(restart)")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeDenyCommand, vtype)
	assert.Equal(t, "(request)|(restart)", string(val))
}

func TestNewAllowConfiguration_RoundTrip(t *testing.T) {
	attr := NewAllowConfiguration("(system radius-server)")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeAllowConfiguration, vtype)
	assert.Equal(t, "(system radius-server)", string(val))
}

func TestNewDenyConfiguration_RoundTrip(t *testing.T) {
	attr := NewDenyConfiguration("(system accounting)")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeDenyConfiguration, vtype)
	assert.Equal(t, "(system accounting)", string(val))
}

func TestNewInteractiveCommand_RoundTrip(t *testing.T) {
	attr := NewInteractiveCommand("show version")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeInteractiveCommand, vtype)
	assert.Equal(t, "show version", string(val))
}

func TestNewConfigurationChange_RoundTrip(t *testing.T) {
	attr := NewConfigurationChange("set system host-name r1")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeConfigurationChange, vtype)
	assert.Equal(t, "set system host-name r1", string(val))
}

func TestNewUserPermissions_RoundTrip(t *testing.T) {
	attr := NewUserPermissions("interface interface-control configure")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeUserPermissions, vtype)
	assert.Equal(t, "interface interface-control configure", string(val))
}

func TestNewAuthenticationType_RoundTrip(t *testing.T) {
	for method, want := range map[string]string{
		AuthenticationTypeLocal:  AuthenticationTypeLocal,
		AuthenticationTypeRemote: AuthenticationTypeRemote,
	} {
		t.Run(method, func(t *testing.T) {
			attr := NewAuthenticationType(method)
			vtype, val, ok := Decode(attr)
			require.True(t, ok)
			assert.Equal(t, VendorTypeAuthenticationType, vtype)
			assert.Equal(t, want, string(val))
		})
	}
}

func TestNewSessionPort_RoundTrip(t *testing.T) {
	const port uint32 = 49152
	attr := NewSessionPort(port)
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeSessionPort, vtype)
	require.Len(t, val, 4, "Juniper-Session-Port value must be a 4-byte integer")
	assert.Equal(t, port, binary.BigEndian.Uint32(val))
}

func TestNewAllowConfigurationRegexps_RoundTrip(t *testing.T) {
	attr := NewAllowConfigurationRegexps("(groups re0)|(system ntp)")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeAllowConfigurationRegexps, vtype)
	assert.Equal(t, "(groups re0)|(system ntp)", string(val))
}

func TestNewDenyConfigurationRegexps_RoundTrip(t *testing.T) {
	attr := NewDenyConfigurationRegexps("(system login)|(system services)")
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeDenyConfigurationRegexps, vtype)
	assert.Equal(t, "(system login)|(system services)", string(val))
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
