package huawei

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// kind tags for the table-driven round-trip cases.
const (
	kindStr = iota
	kindInt
	kindIPv6
)

type rtCase struct {
	name  string
	attr  func() packet.Attribute
	vtype byte
	kind  int
	want  string // kindStr
	iwant uint32 // kindInt
	ip    net.IP // kindIPv6
}

// rtCases lists every typed constructor. Each is decoded back and the
// vendor-type and value are checked against the input.
var rtCases = []rtCase{
	// --- rate / burst family (sub-types 1-6) ---
	{"InputPeakInformationRate", func() packet.Attribute { return NewInputPeakInformationRate(10000000) }, VendorTypeInputPeakInformationRate, kindInt, "", 10000000, nil},
	{"InputCommittedInformationRate", func() packet.Attribute { return NewInputCommittedInformationRate(5000000) }, VendorTypeInputCommittedInformationRate, kindInt, "", 5000000, nil},
	{"InputCommittedBurstSize", func() packet.Attribute { return NewInputCommittedBurstSize(80000) }, VendorTypeInputCommittedBurstSize, kindInt, "", 80000, nil},
	{"OutputPeakInformationRate", func() packet.Attribute { return NewOutputPeakInformationRate(20000000) }, VendorTypeOutputPeakInformationRate, kindInt, "", 20000000, nil},
	{"OutputCommittedInformationRate", func() packet.Attribute { return NewOutputCommittedInformationRate(5000000) }, VendorTypeOutputCommittedInformationRate, kindInt, "", 5000000, nil},
	{"OutputCommittedBurstSize", func() packet.Attribute { return NewOutputCommittedBurstSize(80000) }, VendorTypeOutputCommittedBurstSize, kindInt, "", 80000, nil},

	// --- access / management sub-types ---
	{"UserNameAccessLimit", func() packet.Attribute { return NewUserNameAccessLimit(0xFFFFFFFF) }, VendorTypeUserNameAccessLimit, kindInt, "", 0xFFFFFFFF, nil},
	{"ConnectID", func() packet.Attribute { return NewConnectID(42) }, VendorTypeConnectID, kindInt, "", 42, nil},
	{"FTPDirectory", func() packet.Attribute { return NewFTPDirectory("/ftp/users") }, VendorTypeFTPDirectory, kindStr, "/ftp/users", 0, nil},
	{"ExecPrivilege", func() packet.Attribute { return NewExecPrivilege(3) }, VendorTypeExecPrivilege, kindInt, "", 3, nil},
	{"QoSData", func() packet.Attribute { return NewQoSData("tpl-up-10m") }, VendorTypeQoSData, kindStr, "tpl-up-10m", 0, nil},
	{"VoiceVLAN", func() packet.Attribute { return NewVoiceVLAN(1) }, VendorTypeVoiceVLAN, kindInt, "", 1, nil},
	{"NASStartupTimeStamp", func() packet.Attribute { return NewNASStartupTimeStamp(1700000000) }, VendorTypeNASStartupTimeStamp, kindInt, "", 1700000000, nil},
	{"IPHostAddress", func() packet.Attribute { return NewIPHostAddress("10.1.1.1 aa:bb:cc:dd:ee:ff") }, VendorTypeIPHostAddress, kindStr, "10.1.1.1 aa:bb:cc:dd:ee:ff", 0, nil},
	{"UpPriority", func() packet.Attribute { return NewUpPriority(5) }, VendorTypeUpPriority, kindInt, "", 5, nil},
	{"DownPriority", func() packet.Attribute { return NewDownPriority(5) }, VendorTypeDownPriority, kindInt, "", 5, nil},
	{"DataFilter", func() packet.Attribute { return NewDataFilter("$1 permit dst 10.0.0.0/8") }, VendorTypeDataFilter, kindStr, "$1 permit dst 10.0.0.0/8", 0, nil},
	{"DomainName", func() packet.Attribute { return NewDomainName("huawei") }, VendorTypeDomainName, kindStr, "huawei", 0, nil},
	{"APInformation", func() packet.Attribute { return NewAPInformation("00e0-fc00-1234") }, VendorTypeAPInformation, kindStr, "00e0-fc00-1234", 0, nil},
	{"UserInformation", func() packet.Attribute { return NewUserInformation("security-check") }, VendorTypeUserInformation, kindStr, "security-check", 0, nil},
	{"UserPolicy", func() packet.Attribute { return NewUserPolicy("svc-profile-1") }, VendorTypeUserPolicy, kindStr, "svc-profile-1", 0, nil},
	{"AccessType", func() packet.Attribute { return NewAccessType(6) }, VendorTypeAccessType, kindInt, "", 6, nil},
	{"PortalURL", func() packet.Attribute { return NewPortalURL("https://example.com/redirect") }, VendorTypePortalURL, kindStr, "https://example.com/redirect", 0, nil},
	{"DHCPOption", func() packet.Attribute { return NewDHCPOption("\x35\x01\x01") }, VendorTypeDHCPOption, kindStr, "\x35\x01\x01", 0, nil},
	{"UCLGroup", func() packet.Attribute { return NewUCLGroup(100) }, VendorTypeUCLGroup, kindInt, "", 100, nil},
	{"LLDP", func() packet.Attribute { return NewLLDP("\x05\x04Huawei") }, VendorTypeLLDP, kindStr, "\x05\x04Huawei", 0, nil},
	{"MDN", func() packet.Attribute { return NewMDN("\x01\x04abcd") }, VendorTypeMDN, kindStr, "\x01\x04abcd", 0, nil},

	// --- IPv6 accounting sub-types ---
	{"AcctIPv6InputOctets", func() packet.Attribute { return NewAcctIPv6InputOctets(123456) }, VendorTypeAcctIPv6InputOctets, kindInt, "", 123456, nil},
	{"AcctIPv6OutputOctets", func() packet.Attribute { return NewAcctIPv6OutputOctets(654321) }, VendorTypeAcctIPv6OutputOctets, kindInt, "", 654321, nil},
	{"AcctIPv6InputPackets", func() packet.Attribute { return NewAcctIPv6InputPackets(7) }, VendorTypeAcctIPv6InputPackets, kindInt, "", 7, nil},
	{"AcctIPv6OutputPackets", func() packet.Attribute { return NewAcctIPv6OutputPackets(9) }, VendorTypeAcctIPv6OutputPackets, kindInt, "", 9, nil},
	{"AcctIPv6InputGigawords", func() packet.Attribute { return NewAcctIPv6InputGigawords(2) }, VendorTypeAcctIPv6InputGigawords, kindInt, "", 2, nil},
	{"AcctIPv6OutputGigawords", func() packet.Attribute { return NewAcctIPv6OutputGigawords(3) }, VendorTypeAcctIPv6OutputGigawords, kindInt, "", 3, nil},

	// --- ACL / redirect / policy / misc sub-types ---
	{"RedirectACL", func() packet.Attribute { return NewRedirectACL("3100") }, VendorTypeRedirectACL, kindStr, "3100", 0, nil},
	{"IPv6RedirectACL", func() packet.Attribute { return NewIPv6RedirectACL("3101") }, VendorTypeIPv6RedirectACL, kindStr, "3101", 0, nil},
	{"MACsecPolicy", func() packet.Attribute { return NewMACsecPolicy("must-secure") }, VendorTypeMACsecPolicy, kindStr, "must-secure", 0, nil},
	{"AVPair", func() packet.Attribute { return NewAVPair("ipv6-redirect-url=https://x") }, VendorTypeAVPair, kindStr, "ipv6-redirect-url=https://x", 0, nil},
	{"MUDURL", func() packet.Attribute { return NewMUDURL("https://mud.example.com/mud.json") }, VendorTypeMUDURL, kindStr, "https://mud.example.com/mud.json", 0, nil},
	{"VIPLevelID", func() packet.Attribute { return NewVIPLevelID(1) }, VendorTypeVIPLevelID, kindInt, "", 1, nil},
	{"ExtSpecific", func() packet.Attribute { return NewExtSpecific("user-dscp-in=46") }, VendorTypeExtSpecific, kindStr, "user-dscp-in=46", 0, nil},
	{"UserAccessInfo", func() packet.Attribute { return NewUserAccessInfo("info") }, VendorTypeUserAccessInfo, kindStr, "info", 0, nil},
	{"AccessDeviceInfo", func() packet.Attribute { return NewAccessDeviceInfo("dev") }, VendorTypeAccessDeviceInfo, kindStr, "dev", 0, nil},
	{"ReachableDetect", func() packet.Attribute { return NewReachableDetect("ok") }, VendorTypeReachableDetect, kindStr, "ok", 0, nil},
	{"IPv6FilterID", func() packet.Attribute { return NewIPv6FilterID("3001") }, VendorTypeIPv6FilterID, kindStr, "3001", 0, nil},
	{"FramedIPv6Address", func() packet.Attribute { return NewFramedIPv6Address(net.ParseIP("2001:db8::1")) }, VendorTypeFramedIPv6Address, kindIPv6, "", 0, net.ParseIP("2001:db8::1")},
	{"Version", func() packet.Attribute { return NewVersion("V600R025C00") }, VendorTypeVersion, kindStr, "V600R025C00", 0, nil},
	{"ProductID", func() packet.Attribute { return NewProductID("S5700") }, VendorTypeProductID, kindStr, "S5700", 0, nil},
}

func TestRoundTrip(t *testing.T) {
	for _, tc := range rtCases {
		t.Run(tc.name, func(t *testing.T) {
			attr := tc.attr()
			vtype, val, ok := Decode(attr)
			require.True(t, ok, "Decode should recognize Huawei VSA")
			assert.Equal(t, tc.vtype, vtype)
			switch tc.kind {
			case kindStr:
				assert.Equal(t, tc.want, string(val))
			case kindInt:
				require.Len(t, val, 4, "integer VSA value must be 4 bytes big-endian")
				assert.Equal(t, tc.iwant, binary.BigEndian.Uint32(val))
			case kindIPv6:
				require.Len(t, val, 16, "IPv6 VSA value must be 16 bytes")
				assert.Equal(t, []byte(tc.ip.To16()), val)
			}
		})
	}
}

func TestNew_ExplicitType(t *testing.T) {
	attr := New(VendorTypeDataFilter, []byte("$1 deny"))
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeDataFilter, vtype)
	assert.Equal(t, "$1 deny", string(val))
}

func TestNewFramedIPv6Address_NonIPv6(t *testing.T) {
	// A non-IPv6-convertible input yields 16 zero bytes rather than a panic.
	attr := NewFramedIPv6Address(nil)
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeFramedIPv6Address, vtype)
	require.Len(t, val, 16)
	assert.Equal(t, make([]byte, 16), val)
}

func TestDecode_NonHuaweiRejected(t *testing.T) {
	// Cisco (Vendor-Id 9) and H3C (Vendor-Id 25506) must not be
	// recognized as Huawei, which now uniquely owns 2011.
	for _, vid := range []uint32{9, 25506} {
		other := vendors.NewVSA(vid, 1, []byte("x"))
		_, _, ok := Decode(other)
		assert.False(t, ok, "Vendor-Id %d must not decode as Huawei", vid)
	}
}

func TestDecode_VendorID2011IsHuawei(t *testing.T) {
	// H3C has migrated to its own code 25506, so a Vendor-Id 2011 VSA
	// is now unambiguously a Huawei VSA.
	attr := vendors.NewVSA(2011, 1, []byte{0, 0, 0, 0x0A})
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, byte(1), vtype)
	assert.Equal(t, []byte{0, 0, 0, 0x0A}, val)
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(2011), VendorID)
}

func TestSubTypeConstants_MatchDoc(t *testing.T) {
	// Spot-check a representative subset of sub-type numbers against the
	// Huawei documentation table, guarding against accidental renumbering.
	cases := map[byte]byte{
		VendorTypeInputPeakInformationRate: 1,
		VendorTypeOutputCommittedBurstSize: 6,
		VendorTypeUserNameAccessLimit:      18,
		VendorTypeExecPrivilege:            29,
		VendorTypeDataFilter:               82,
		VendorTypeUserPolicy:               146,
		VendorTypeAcctIPv6InputOctets:      166,
		VendorTypeAcctIPv6OutputGigawords:  171,
		VendorTypeAVPair:                   188,
		VendorTypeExtSpecific:              238,
		VendorTypeIPv6FilterID:             251,
		VendorTypeFramedIPv6Address:        253,
		VendorTypeProductID:                255,
	}
	for konst, want := range cases {
		assert.Equalf(t, want, konst, "sub-type constant mismatch")
	}
}
