package microsoft

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
	"github.com/wxccs/radius/v2/vendors"
)

// TestNAPNPASConstants pins the Vendor-Type numbers for every VSA
// defined by MS-RNAP (NAP, v19.0) and MS-RNAS (NPAS, v7.0). The
// 0x26/0x27/0x2B gap is intentional: those numbers belong to the
// RFC 2548 MS-CHAP family declared in microsoft.go.
func TestNAPNPASConstants(t *testing.T) {
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"RASClientName", VendorTypeRASClientName, 0x22},
		{"RASClientVersion", VendorTypeRASClientVersion, 0x23},
		{"QuarantineIPFilter", VendorTypeQuarantineIPFilter, 0x24},
		{"QuarantineSessionTimeout", VendorTypeQuarantineSessionTimeout, 0x25},
		{"UserSecurityIdentity", VendorTypeUserSecurityIdentity, 0x28},
		{"IdentityType", VendorTypeIdentityType, 0x29},
		{"ServiceClass", VendorTypeServiceClass, 0x2A},
		{"QuarantineUserClass", VendorTypeQuarantineUserClass, 0x2C},
		{"QuarantineState", VendorTypeQuarantineState, 0x2D},
		{"QuarantineGraceTime", VendorTypeQuarantineGraceTime, 0x2E},
		{"NetworkAccessServerType", VendorTypeNetworkAccessServerType, 0x2F},
		{"AFWZone", VendorTypeAFWZone, 0x30},
		{"AFWProtectionLevel", VendorTypeAFWProtectionLevel, 0x31},
		{"MachineName", VendorTypeMachineName, 0x32},
		{"IPv6Filter", VendorTypeIPv6Filter, 0x33},
		{"IPv4RemediationServers", VendorTypeIPv4RemediationServers, 0x34},
		{"IPv6RemediationServers", VendorTypeIPv6RemediationServers, 0x35},
		{"NotQuarantineCapable", VendorTypeNotQuarantineCapable, 0x36},
		{"QuarantineSoH", VendorTypeQuarantineSoH, 0x37},
		{"RASCorrelationID", VendorTypeRASCorrelationID, 0x38},
		{"ExtendedQuarantineState", VendorTypeExtendedQuarantineState, 0x39},
		{"HCAPUserGroups", VendorTypeHCAPUserGroups, 0x3A},
		{"HCAPLocationGroupName", VendorTypeHCAPLocationGroupName, 0x3B},
		{"HCAPUserName", VendorTypeHCAPUserName, 0x3C},
		{"UserIPv4Address", VendorTypeUserIPv4Address, 0x3D},
		{"UserIPv6Address", VendorTypeUserIPv6Address, 0x3E},
		{"RDGDeviceRedirection", VendorTypeRDGDeviceRedirection, 0x3F},
		{"AzurePolicyID", VendorTypeAzurePolicyID, 0x41},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, c.got, "VendorType%s", c.name)
	}
	// 2.2.2.1: SSTP vendor-specific value for the standard Tunnel-Type
	// (Type 64) attribute. Encoded as Microsoft enterprise ID (0x0137) ||
	// tag 0 || 0x01 in network byte order.
	assert.Equal(t, uint32(0x00013701), TunnelTypeSSTP)
}

// TestEnumConstants pins the enumerated values defined by MS-RNAP for
// the 32-bit VSA families.
func TestEnumConstants(t *testing.T) {
	assert.Equal(t, uint32(0x00000001), IdentityTypeMachine)

	assert.Equal(t, uint32(0x00000000), QuarantineStateFullAccess)
	assert.Equal(t, uint32(0x00000001), QuarantineStateRestricted)
	assert.Equal(t, uint32(0x00000002), QuarantineStateOnProbation)

	assert.Equal(t, uint32(0x00000000), NASTypeUnspecified)
	assert.Equal(t, uint32(0x00000001), NASTypeTerminalServerGateway)
	assert.Equal(t, uint32(0x00000002), NASTypeRAS)
	assert.Equal(t, uint32(0x00000003), NASTypeDHCP)
	assert.Equal(t, uint32(0x00000005), NASTypeHRA)
	assert.Equal(t, uint32(0x00000006), NASTypeHCAP)

	assert.Equal(t, uint32(0x00000001), AFWZoneEncryptionRequired)
	assert.Equal(t, uint32(0x00000002), AFWZoneEncryptionNotRequired)
	assert.Equal(t, uint32(0x00000003), AFWZoneEncryptionRequiredAlt)

	assert.Equal(t, uint32(0x00000001), AFWProtectionLevelValue1)
	assert.Equal(t, uint32(0x00000002), AFWProtectionLevelValue2)

	// Value 0 means the endpoint DID send an SoH; 1 means it did not.
	assert.Equal(t, uint32(0x00000000), NotQuarantineCapableSoHSent)
	assert.Equal(t, uint32(0x00000001), NotQuarantineCapableSoHNotSent)

	assert.Equal(t, uint32(0x00000000), ExtendedQuarantineStateNoData)
	assert.Equal(t, uint32(0x00000001), ExtendedQuarantineStateTransition)
	assert.Equal(t, uint32(0x00000002), ExtendedQuarantineStateInfected)
	assert.Equal(t, uint32(0x00000003), ExtendedQuarantineStateUnknown)

	// MS-RDG-Device-Redirection bitmask (bit 0 = least significant).
	assert.Equal(t, uint32(1<<0), RDGRedirDrives)
	assert.Equal(t, uint32(1<<1), RDGRedirPrinters)
	assert.Equal(t, uint32(1<<2), RDGRedirSerialPorts)
	assert.Equal(t, uint32(1<<3), RDGRedirClipboard)
	assert.Equal(t, uint32(1<<4), RDGRedirPlugAndPlay)
	assert.Equal(t, uint32(1<<29), RDGRedirDisableAll)
	assert.Equal(t, uint32(1<<30), RDGRedirEnableAll)
}

// TestNewStringVSAs verifies the ASCII/ANSI string VSA families wrap the
// value verbatim, and that MS-RAS-Client-Name is null-terminated per the
// MS-RNAP "MUST be null terminated" requirement.
func TestNewStringVSAs(t *testing.T) {
	t.Run("RASClientName null-terminated", func(t *testing.T) {
		attr := NewRASClientName("host01")
		vt, val, ok := Decode(attr)
		require.True(t, ok)
		assert.Equal(t, VendorTypeRASClientName, vt)
		assert.Equal(t, []byte("host01\x00"), val, "MS-RAS-Client-Name MUST be null terminated")
	})

	stringCases := []struct {
		name string
		vt   byte
		fn   func(string) packet.Attribute
	}{
		{"RASClientVersion", VendorTypeRASClientVersion, NewRASClientVersion},
		{"ServiceClass", VendorTypeServiceClass, NewServiceClass},
		{"QuarantineUserClass", VendorTypeQuarantineUserClass, NewQuarantineUserClass},
		{"MachineName", VendorTypeMachineName, NewMachineName},
		{"HCAPUserGroups", VendorTypeHCAPUserGroups, NewHCAPUserGroups},
		{"HCAPLocationGroupName", VendorTypeHCAPLocationGroupName, NewHCAPLocationGroupName},
		{"HCAPUserName", VendorTypeHCAPUserName, NewHCAPUserName},
		{"AzurePolicyID", VendorTypeAzurePolicyID, NewAzurePolicyID},
	}
	for _, c := range stringCases {
		t.Run(c.name, func(t *testing.T) {
			attr := c.fn("value-" + c.name)
			vt, val, ok := Decode(attr)
			require.True(t, ok)
			assert.Equal(t, c.vt, vt)
			assert.Equal(t, []byte("value-"+c.name), val, "string VSA value must be verbatim")
		})
	}
}

// TestNewUint32VSAs verifies the 32-bit integer VSAs encode the value in
// network (big-endian) byte order with a 4-byte Attribute-Specific Value.
func TestNewUint32VSAs(t *testing.T) {
	cases := []struct {
		name string
		vt   byte
		attr packet.Attribute
	}{
		{"QuarantineSessionTimeout", VendorTypeQuarantineSessionTimeout, NewQuarantineSessionTimeout(300)},
		{"IdentityType", VendorTypeIdentityType, NewIdentityType(IdentityTypeMachine)},
		{"QuarantineState", VendorTypeQuarantineState, NewQuarantineState(QuarantineStateOnProbation)},
		{"QuarantineGraceTime", VendorTypeQuarantineGraceTime, NewQuarantineGraceTime(0x01020304)},
		{"NetworkAccessServerType", VendorTypeNetworkAccessServerType, NewNetworkAccessServerType(NASTypeHRA)},
		{"AFWZone", VendorTypeAFWZone, NewAFWZone(AFWZoneEncryptionRequiredAlt)},
		{"AFWProtectionLevel", VendorTypeAFWProtectionLevel, NewAFWProtectionLevel(AFWProtectionLevelValue2)},
		{"NotQuarantineCapable", VendorTypeNotQuarantineCapable, NewNotQuarantineCapable(NotQuarantineCapableSoHNotSent)},
		{"ExtendedQuarantineState", VendorTypeExtendedQuarantineState, NewExtendedQuarantineState(ExtendedQuarantineStateInfected)},
		{"RDGDeviceRedirection", VendorTypeRDGDeviceRedirection, NewRDGDeviceRedirection(RDGRedirDisableAll)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vt, val, ok := Decode(c.attr)
			require.True(t, ok)
			assert.Equal(t, c.vt, vt)
			require.Len(t, val, 4, "32-bit VSA value must be exactly 4 bytes")
			// Verify big-endian decoding against the known input where
			// the value is unambiguous.
			switch c.name {
			case "QuarantineSessionTimeout":
				assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x2C}, val)
			case "QuarantineGraceTime":
				assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, val)
			case "NetworkAccessServerType":
				assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x05}, val) // HRA = 5
			case "RDGDeviceRedirection":
				assert.Equal(t, []byte{0x20, 0x00, 0x00, 0x00}, val) // 1<<29 big-endian
			}
		})
	}
}

// TestNewAddressVSAs verifies the IP-address VSAs store the address in
// its wire (network) byte order.
func TestNewAddressVSAs(t *testing.T) {
	t.Run("UserIPv4Address", func(t *testing.T) {
		attr := NewUserIPv4Address(net.IPv4(10, 0, 0, 1))
		vt, val, ok := Decode(attr)
		require.True(t, ok)
		assert.Equal(t, VendorTypeUserIPv4Address, vt)
		require.Len(t, val, 4)
		assert.Equal(t, []byte{10, 0, 0, 1}, val)
	})

	t.Run("UserIPv6Address", func(t *testing.T) {
		ip := net.ParseIP("2001:0db8::1")
		attr := NewUserIPv6Address(ip)
		vt, val, ok := Decode(attr)
		require.True(t, ok)
		assert.Equal(t, VendorTypeUserIPv6Address, vt)
		require.Len(t, val, 16)
		assert.Equal(t, []byte(ip.To16()), val)
	})
}

// TestNewRemediationServers verifies the reserved leading byte (0) and
// the trailing list of IPv4 (4 bytes) / IPv6 (16 bytes) addresses.
func TestNewRemediationServers(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		ips := []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(192, 168, 1, 5)}
		attr := NewIPv4RemediationServers(ips)
		vt, val, ok := Decode(attr)
		require.True(t, ok)
		assert.Equal(t, VendorTypeIPv4RemediationServers, vt)
		// 1 reserved byte + 2 * 4 bytes.
		require.Len(t, val, 9)
		assert.Equal(t, byte(0), val[0], "reserved byte MUST be 0")
		assert.Equal(t, []byte{10, 0, 0, 1, 192, 168, 1, 5}, val[1:])
	})

	t.Run("IPv6", func(t *testing.T) {
		ip1 := net.ParseIP("2001:db8::1")
		ip2 := net.ParseIP("2001:db8::2")
		attr := NewIPv6RemediationServers([]net.IP{ip1, ip2})
		vt, val, ok := Decode(attr)
		require.True(t, ok)
		assert.Equal(t, VendorTypeIPv6RemediationServers, vt)
		// 1 reserved byte + 2 * 16 bytes.
		require.Len(t, val, 33)
		assert.Equal(t, byte(0), val[0])
		assert.Equal(t, []byte(ip1.To16()), val[1:17])
		assert.Equal(t, []byte(ip2.To16()), val[17:33])
	})

	t.Run("IPv4 empty still carries reserved byte", func(t *testing.T) {
		attr := NewIPv4RemediationServers(nil)
		_, val, ok := Decode(attr)
		require.True(t, ok)
		require.Len(t, val, 1)
		assert.Equal(t, byte(0), val[0])
	})
}

// TestNewRASCorrelationID verifies the GUID is carried as its curly-braced
// string form, verbatim.
func TestNewRASCorrelationID(t *testing.T) {
	guid := "{12345678-1234-1234-1234-123456789abc}"
	attr := NewRASCorrelationID(guid)
	vt, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeRASCorrelationID, vt)
	assert.Equal(t, guid, string(val))
}

// TestNewRawVSAs verifies the complex binary VSAs carry their raw bytes
// verbatim. IPFilter/IPv6Filter/SID/SoH are multi-layer structures whose
// full typed builders are out of scope for this update.
func TestNewRawVSAs(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
	cases := []struct {
		name string
		vt   byte
		attr packet.Attribute
	}{
		{"QuarantineIPFilter", VendorTypeQuarantineIPFilter, NewQuarantineIPFilter(raw)},
		{"IPv6Filter", VendorTypeIPv6Filter, NewIPv6Filter(raw)},
		{"UserSecurityIdentity", VendorTypeUserSecurityIdentity, NewUserSecurityIdentity(raw)},
		{"QuarantineSoH", VendorTypeQuarantineSoH, NewQuarantineSoH(raw)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vt, val, ok := Decode(c.attr)
			require.True(t, ok)
			assert.Equal(t, c.vt, vt)
			assert.Equal(t, raw, val)
		})
	}
}

// TestNew_Generic confirms the generic constructor wraps an arbitrary
// vendor-type/value pair in a Microsoft VSA.
func TestNew_Generic(t *testing.T) {
	attr := New(VendorTypeMachineName, []byte("raw"))
	vt, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeMachineName, vt)
	assert.Equal(t, []byte("raw"), val)
}

// TestNewTunnelTypeSSTP verifies the SSTP vendor-specific value for the
// standard Tunnel-Type (Type 64) attribute is encoded as 0x00013701.
func TestNewTunnelTypeSSTP(t *testing.T) {
	attr := NewTunnelTypeSSTP()

	// It is a standard RADIUS attribute, not a VSA.
	assert.Equal(t, byte(types.AttrTunnelType), attr.Type)

	n, err := attr.Integer()
	require.NoError(t, err)
	assert.Equal(t, uint32(0x00013701), n)

	// 0x00013701 in big-endian wire bytes.
	require.Len(t, attr.Value, 4)
	assert.Equal(t, []byte{0x00, 0x01, 0x37, 0x01}, attr.Value)
}

// TestNAPNPASDecode_NonMicrosoftRejected ensures the generic Decode
// helper still rejects VSAs carrying another vendor's Vendor-Id.
func TestNAPNPASDecode_NonMicrosoftRejected(t *testing.T) {
	ciscoAttr := vendors.NewVSA(9, VendorTypeMachineName, []byte("x"))
	_, _, ok := Decode(ciscoAttr)
	assert.False(t, ok, "a Cisco VSA must not decode as Microsoft")
}
