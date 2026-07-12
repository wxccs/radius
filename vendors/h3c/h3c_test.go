package h3c

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

const (
	kindStr = iota
	kindInt
	kindIPv4
	kindOctets
)

type rtCase struct {
	name  string
	attr  func() packet.Attribute
	vtype byte
	kind  int
	want  string
	iwant uint32
	ip    net.IP
}

// rtCases lists every typed constructor; each is decoded back and the
// vendor-type and value are checked against the input.
var rtCases = []rtCase{
	// --- rate family (sub-types 1-6) ---
	{"InputPeakRate", func() packet.Attribute { return NewInputPeakRate(10000000) }, VendorTypeInputPeakRate, kindInt, "", 10000000, nil},
	{"InputAverageRate", func() packet.Attribute { return NewInputAverageRate(5000000) }, VendorTypeInputAverageRate, kindInt, "", 5000000, nil},
	{"InputBasicRate", func() packet.Attribute { return NewInputBasicRate(2000000) }, VendorTypeInputBasicRate, kindInt, "", 2000000, nil},
	{"OutputPeakRate", func() packet.Attribute { return NewOutputPeakRate(20000000) }, VendorTypeOutputPeakRate, kindInt, "", 20000000, nil},
	{"OutputAverageRate", func() packet.Attribute { return NewOutputAverageRate(5000000) }, VendorTypeOutputAverageRate, kindInt, "", 5000000, nil},
	{"OutputBasicRate", func() packet.Attribute { return NewOutputBasicRate(2000000) }, VendorTypeOutputBasicRate, kindInt, "", 2000000, nil},

	// --- session / control sub-types ---
	{"RemanentVolume", func() packet.Attribute { return NewRemanentVolume(1048576) }, VendorTypeRemanentVolume, kindInt, "", 1048576, nil},
	{"Command", func() packet.Attribute { return NewCommand(1) }, VendorTypeCommand, kindInt, "", 1, nil},
	{"ControlIdentifier", func() packet.Attribute { return NewControlIdentifier(7) }, VendorTypeControlIdentifier, kindInt, "", 7, nil},
	{"ResultCode", func() packet.Attribute { return NewResultCode(0) }, VendorTypeResultCode, kindInt, "", 0, nil},
	{"ConnectID", func() packet.Attribute { return NewConnectID(42) }, VendorTypeConnectID, kindInt, "", 42, nil},
	{"FTPDirectory", func() packet.Attribute { return NewFTPDirectory("/ftp/users") }, VendorTypeFTPDirectory, kindStr, "/ftp/users", 0, nil},
	{"ExecPrivilege", func() packet.Attribute { return NewExecPrivilege(3) }, VendorTypeExecPrivilege, kindInt, "", 3, nil},
	{"NASStartupTimestamp", func() packet.Attribute { return NewNASStartupTimestamp(1700000000) }, VendorTypeNASStartupTimestamp, kindInt, "", 1700000000, nil},
	{"IPHostAddr", func() packet.Attribute { return NewIPHostAddr("10.1.1.1 aa:bb:cc:dd:ee:ff") }, VendorTypeIPHostAddr, kindStr, "10.1.1.1 aa:bb:cc:dd:ee:ff", 0, nil},
	{"UserNotify", func() packet.Attribute { return NewUserNotify("notify-msg") }, VendorTypeUserNotify, kindStr, "notify-msg", 0, nil},
	{"UserHeartbeat", func() packet.Attribute { return NewUserHeartbeat([]byte("0123456789ABCDEF0123456789ABCDEF")) }, VendorTypeUserHeartbeat, kindOctets, "0123456789ABCDEF0123456789ABCDEF", 0, nil},
	{"UserGroup", func() packet.Attribute { return NewUserGroup("grp1;grp2") }, VendorTypeUserGroup, kindStr, "grp1;grp2", 0, nil},
	{"SecurityLevel", func() packet.Attribute { return NewSecurityLevel(2) }, VendorTypeSecurityLevel, kindInt, "", 2, nil},

	// --- realtime accounting interval sub-types ---
	{"InputIntervalOctets", func() packet.Attribute { return NewInputIntervalOctets(123456) }, VendorTypeInputIntervalOctets, kindInt, "", 123456, nil},
	{"OutputIntervalOctets", func() packet.Attribute { return NewOutputIntervalOctets(654321) }, VendorTypeOutputIntervalOctets, kindInt, "", 654321, nil},
	{"InputIntervalPackets", func() packet.Attribute { return NewInputIntervalPackets(100) }, VendorTypeInputIntervalPackets, kindInt, "", 100, nil},
	{"OutputIntervalPackets", func() packet.Attribute { return NewOutputIntervalPackets(200) }, VendorTypeOutputIntervalPackets, kindInt, "", 200, nil},
	{"InputIntervalGigawords", func() packet.Attribute { return NewInputIntervalGigawords(1) }, VendorTypeInputIntervalGigawords, kindInt, "", 1, nil},
	{"OutputIntervalGigawords", func() packet.Attribute { return NewOutputIntervalGigawords(2) }, VendorTypeOutputIntervalGigawords, kindInt, "", 2, nil},

	// --- misc ---
	{"BackupNASIP", func() packet.Attribute { return NewBackupNASIP(net.ParseIP("10.2.3.4")) }, VendorTypeBackupNASIP, kindIPv4, "", 0, net.ParseIP("10.2.3.4")},
	{"ProductID", func() packet.Attribute { return NewProductID("H3C-S5500") }, VendorTypeProductID, kindStr, "H3C-S5500", 0, nil},
}

func TestRoundTrip(t *testing.T) {
	for _, tc := range rtCases {
		t.Run(tc.name, func(t *testing.T) {
			attr := tc.attr()
			vtype, val, ok := Decode(attr)
			require.True(t, ok, "Decode should recognize H3C VSA")
			assert.Equal(t, tc.vtype, vtype)
			switch tc.kind {
			case kindStr:
				assert.Equal(t, tc.want, string(val))
			case kindOctets:
				assert.Equal(t, []byte(tc.want), val)
			case kindInt:
				require.Len(t, val, 4, "integer VSA value must be 4 bytes big-endian")
				assert.Equal(t, tc.iwant, binary.BigEndian.Uint32(val))
			case kindIPv4:
				require.Len(t, val, 4, "IPv4 VSA value must be 4 bytes")
				assert.Equal(t, []byte(tc.ip.To4()), val)
			}
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

func TestNewBackupNASIP_NonIPv4(t *testing.T) {
	// A non-IPv4-convertible input yields 4 zero bytes rather than a panic.
	attr := NewBackupNASIP(nil)
	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeBackupNASIP, vtype)
	require.Len(t, val, 4)
	assert.Equal(t, make([]byte, 4), val)
}

func TestNewUserHeartbeat_Copied(t *testing.T) {
	// The constructor must copy the input slice so callers cannot mutate
	// the attribute's internal buffer afterwards.
	in := []byte("0123456789ABCDEF0123456789ABCDEF")
	attr := NewUserHeartbeat(in)
	in[0] = 'X' // mutate caller's slice
	_, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, byte('0'), val[0], "constructor must not alias caller's slice")
}

func TestDecode_NonH3CRejected(t *testing.T) {
	// Cisco (Vendor-Id 9) and Huawei (Vendor-Id 2011) must not be
	// recognized as H3C (25506).
	for _, vid := range []uint32{9, 2011} {
		other := vendors.NewVSA(vid, 1, []byte("x"))
		_, _, ok := Decode(other)
		assert.False(t, ok, "Vendor-Id %d must not decode as H3C", vid)
	}
}

func TestVendorID_Constant(t *testing.T) {
	assert.Equal(t, uint32(25506), VendorID)
}

func TestSubTypeConstants_MatchDoc(t *testing.T) {
	// Spot-check sub-type numbers against the H3C documentation table,
	// guarding against accidental renumbering. These also assert the
	// corrected values (the previous version of this package had 3-6
	// misnumbered).
	cases := map[byte]byte{
		VendorTypeInputPeakRate:           1,
		VendorTypeInputAverageRate:        2,
		VendorTypeInputBasicRate:          3,
		VendorTypeOutputPeakRate:          4,
		VendorTypeOutputAverageRate:       5,
		VendorTypeOutputBasicRate:         6,
		VendorTypeRemanentVolume:          15,
		VendorTypeCommand:                 20,
		VendorTypeControlIdentifier:       24,
		VendorTypeResultCode:              25,
		VendorTypeConnectID:               26,
		VendorTypeFTPDirectory:            28,
		VendorTypeExecPrivilege:           29,
		VendorTypeNASStartupTimestamp:     59,
		VendorTypeIPHostAddr:              60,
		VendorTypeUserNotify:              61,
		VendorTypeUserHeartbeat:           62,
		VendorTypeUserGroup:               140,
		VendorTypeSecurityLevel:           141,
		VendorTypeInputIntervalOctets:     201,
		VendorTypeOutputIntervalOctets:    202,
		VendorTypeInputIntervalPackets:    203,
		VendorTypeOutputIntervalPackets:   204,
		VendorTypeInputIntervalGigawords:  205,
		VendorTypeOutputIntervalGigawords: 206,
		VendorTypeBackupNASIP:             207,
		VendorTypeProductID:               255,
	}
	for konst, want := range cases {
		assert.Equalf(t, want, konst, "sub-type constant mismatch")
	}
}
