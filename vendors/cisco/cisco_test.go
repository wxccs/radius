package cisco

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// strCases lists every string-valued Cisco VSA constructor; each is
// decoded back and the vendor-type and value are checked.
var strCases = []struct {
	name string
	ctor func(string) packet.Attribute
	vt   byte
}{
	{"AVPair", NewAVPair, VendorTypeAVPair},
	{"NASPort", NewNASPort, VendorTypeNASPort},
	{"FaxAccountIDOrigin", NewFaxAccountIDOrigin, VendorTypeFaxAccountIDOrigin},
	{"FaxMsgID", NewFaxMsgID, VendorTypeFaxMsgID},
	{"FaxPages", NewFaxPages, VendorTypeFaxPages},
	{"FaxCoverpageFlag", NewFaxCoverpageFlag, VendorTypeFaxCoverpageFlag},
	{"FaxModemTime", NewFaxModemTime, VendorTypeFaxModemTime},
	{"FaxConnectSpeed", NewFaxConnectSpeed, VendorTypeFaxConnectSpeed},
	{"FaxRecipientCount", NewFaxRecipientCount, VendorTypeFaxRecipientCount},
	{"FaxProcessAbortFlag", NewFaxProcessAbortFlag, VendorTypeFaxProcessAbortFlag},
	{"FaxDsnAddress", NewFaxDsnAddress, VendorTypeFaxDsnAddress},
	{"FaxDsnFlag", NewFaxDsnFlag, VendorTypeFaxDsnFlag},
	{"FaxMdnAddress", NewFaxMdnAddress, VendorTypeFaxMdnAddress},
	{"FaxMdnFlag", NewFaxMdnFlag, VendorTypeFaxMdnFlag},
	{"FaxAuthStatus", NewFaxAuthStatus, VendorTypeFaxAuthStatus},
	{"EmailServerAddress", NewEmailServerAddress, VendorTypeEmailServerAddress},
	{"EmailServerAckFlag", NewEmailServerAckFlag, VendorTypeEmailServerAckFlag},
	{"FaxGatewayID", NewFaxGatewayID, VendorTypeFaxGatewayID},
	{"FaxCallType", NewFaxCallType, VendorTypeFaxCallType},
	{"PortUsed", NewPortUsed, VendorTypePortUsed},
	{"AbortCause", NewAbortCause, VendorTypeAbortCause},
	{"H323RemoteGatewayID", NewH323RemoteGatewayID, VendorTypeH323RemoteGatewayID},
	{"H323ConnectionID", NewH323ConnectionID, VendorTypeH323ConnectionID},
	{"H323SetupTime", NewH323SetupTime, VendorTypeH323SetupTime},
	{"H323CallOrigin", NewH323CallOrigin, VendorTypeH323CallOrigin},
	{"H323CallType", NewH323CallType, VendorTypeH323CallType},
	{"H323ConnectTime", NewH323ConnectTime, VendorTypeH323ConnectTime},
	{"H323DisconnectTime", NewH323DisconnectTime, VendorTypeH323DisconnectTime},
	{"H323DisconnectCause", NewH323DisconnectCause, VendorTypeH323DisconnectCause},
	{"H323VoiceQuality", NewH323VoiceQuality, VendorTypeH323VoiceQuality},
	{"H323GatewayID", NewH323GatewayID, VendorTypeH323GatewayID},
}

func TestStringConstructors_RoundTrip(t *testing.T) {
	for _, tc := range strCases {
		t.Run(tc.name, func(t *testing.T) {
			val := "value-for-" + tc.name
			attr := tc.ctor(val)
			vtype, got, ok := Decode(attr)
			require.True(t, ok, "Decode should recognize Cisco VSA")
			assert.Equal(t, tc.vt, vtype)
			assert.Equal(t, val, string(got))
		})
	}
}

func TestNewAVPair_Format(t *testing.T) {
	// The cisco-avpair value is "protocol:attribute sep value".
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

func TestSubTypeConstants_MatchDoc(t *testing.T) {
	// Spot-check sub-type numbers against the Cisco IOS 12.2 RADIUS VSA
	// appendix, guarding against accidental renumbering.
	cases := map[byte]byte{
		VendorTypeAVPair:              1,
		VendorTypeNASPort:             2,
		VendorTypeFaxAccountIDOrigin:  3,
		VendorTypeFaxPages:            5,
		VendorTypeFaxConnectSpeed:     8,
		VendorTypeEmailServerAddress:  16,
		VendorTypeFaxGatewayID:        18,
		VendorTypeFaxCallType:         19,
		VendorTypeAbortCause:          21,
		VendorTypeH323RemoteGatewayID: 23,
		VendorTypeH323ConnectionID:    24,
		VendorTypeH323CallOrigin:      26,
		VendorTypeH323CallType:        27,
		VendorTypeH323DisconnectCause: 30,
		VendorTypeH323VoiceQuality:    31,
		VendorTypeH323GatewayID:       33,
	}
	for konst, want := range cases {
		assert.Equalf(t, want, konst, "sub-type constant mismatch")
	}
}
