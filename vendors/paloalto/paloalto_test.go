package paloalto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/types"
	"github.com/wxccs/radius/v2/vendors"
)

// rtCases lists every typed constructor; each is decoded back and the
// vendor-type and string value are checked against the input. All Palo
// Alto VSAs are string-valued per the PAN-OS Administrator's Guide
// RADIUS VSA table (vendor code 25461).
var rtCases = []struct {
	name  string
	attr  func() packet.Attribute
	vtype byte
	want  string
}{
	// --- admin account management and authentication (1-5) ---
	{"AdminRole", func() packet.Attribute { return NewAdminRole("superuser") }, VendorTypeAdminRole, "superuser"},
	{"AdminAccessDomain", func() packet.Attribute { return NewAdminAccessDomain("ad1") }, VendorTypeAdminAccessDomain, "ad1"},
	{"PanoramaAdminRole", func() packet.Attribute { return NewPanoramaAdminRole("superreader") }, VendorTypePanoramaAdminRole, "superreader"},
	{"PanoramaAdminAccessDomain", func() packet.Attribute { return NewPanoramaAdminAccessDomain("pan-ad") }, VendorTypePanoramaAdminAccessDomain, "pan-ad"},
	{"UserGroup", func() packet.Attribute { return NewUserGroup("eng") }, VendorTypeUserGroup, "eng"},
	// --- forwarded from GlobalProtect endpoints (6-10) ---
	{"UserDomain", func() packet.Attribute { return NewUserDomain("corp.example.com") }, VendorTypeUserDomain, "corp.example.com"},
	{"ClientSourceIP", func() packet.Attribute { return NewClientSourceIP("10.0.0.5") }, VendorTypeClientSourceIP, "10.0.0.5"},
	{"ClientOS", func() packet.Attribute { return NewClientOS("Windows 11") }, VendorTypeClientOS, "Windows 11"},
	{"ClientHostname", func() packet.Attribute { return NewClientHostname("DESKTOP-ABC") }, VendorTypeClientHostname, "DESKTOP-ABC"},
	{"GlobalProtectClientVersion", func() packet.Attribute { return NewGlobalProtectClientVersion("6.1.0") }, VendorTypeGlobalProtectClientVersion, "6.1.0"},
}

func TestRoundTrip(t *testing.T) {
	for _, tc := range rtCases {
		t.Run(tc.name, func(t *testing.T) {
			attr := tc.attr()
			vtype, val, ok := Decode(attr)
			require.True(t, ok, "Decode should recognize PaloAlto VSA")
			assert.Equal(t, tc.vtype, vtype)
			assert.Equal(t, tc.want, string(val))
		})
	}
}

func TestNew_ExplicitType(t *testing.T) {
	attr := New(VendorTypeUserGroup, []byte("engineers"))
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeUserGroup, vtype)
	assert.Equal(t, "engineers", string(val))
}

func TestDecode_NonPaloAltoRejected(t *testing.T) {
	// Cisco (9) and Microsoft (311) must not be recognized as PaloAlto
	// (25461).
	for _, vid := range []uint32{9, 311} {
		other := vendors.NewVSA(vid, 1, []byte("x"))
		_, _, ok := Decode(other)
		assert.False(t, ok, "Vendor-Id %d must not decode as PaloAlto", vid)
	}
}

func TestDecode_NonVSARejected(t *testing.T) {
	// A non-Type-26 attribute must not decode as a PaloAlto VSA.
	attr := packet.NewString(types.AttrUserName, "alice")
	_, _, ok := Decode(attr)
	assert.False(t, ok, "non-VSA attribute must not decode as PaloAlto")
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(25461), VendorID)
}

func TestSubTypeConstants_MatchDoc(t *testing.T) {
	// Pin every sub-type number against the PAN-OS Administrator's Guide
	// RADIUS VSA table (vendor code 25461), guarding against accidental
	// renumbering.
	cases := map[byte]byte{
		VendorTypeAdminRole:                  1,
		VendorTypeAdminAccessDomain:          2,
		VendorTypePanoramaAdminRole:          3,
		VendorTypePanoramaAdminAccessDomain:  4,
		VendorTypeUserGroup:                  5,
		VendorTypeUserDomain:                 6,
		VendorTypeClientSourceIP:             7,
		VendorTypeClientOS:                   8,
		VendorTypeClientHostname:             9,
		VendorTypeGlobalProtectClientVersion: 10,
	}
	for konst, want := range cases {
		assert.Equalf(t, want, konst, "sub-type constant mismatch")
	}
}
