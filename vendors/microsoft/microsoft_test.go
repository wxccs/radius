package microsoft

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/v2/crypto"
	radiuserrors "github.com/wxccs/radius/v2/errors"
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// TestNewMSCHAP2Response_WireLayout verifies the outer VSA wraps the
// raw MS-CHAPv2 response bytes verbatim.
func TestNewMSCHAP2Response_WireLayout(t *testing.T) {
	resp := make([]byte, 49)
	for i := range resp {
		resp[i] = byte(i)
	}
	attr := NewMSCHAP2Response(resp)

	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeMSCHAP2Response, vtype)
	assert.Equal(t, resp, val, "VSA value must be the response bytes verbatim")
}

func TestNewMSCHAP2Success_RoundTrip(t *testing.T) {
	resp := "S=0123456789ABCDEF0123456789ABCDEF01234567"
	attr := NewMSCHAP2Success(resp)

	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeMSCHAP2Success, vtype)
	assert.Equal(t, resp, string(val))
}

// TestNewMSCHAP2SuccessFromAuth_FullChain exercises the crypto-package
// integration: given MS-CHAPv2 input parameters, the helper computes
// the Authenticator Response via RFC 2759 and wraps it in a Microsoft
// VSA. The RFC 3079 §3.5 sample produces a known response.
func TestNewMSCHAP2SuccessFromAuth_FullChain(t *testing.T) {
	authChallenge := [crypto.MSCHAPv2ChallengeLength]byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}
	peerChallenge := [crypto.MSCHAPv2ChallengeLength]byte{
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
	}
	ntResponse := [crypto.NTResponseLength]byte{
		0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E,
		0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
		0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
	}
	attr := NewMSCHAP2SuccessFromAuth(authChallenge, peerChallenge,
		ntResponse, "User", "clientPass")

	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeMSCHAP2Success, vtype)

	// The wrapped value must be the "S=" + 40 hex chars response.
	str := string(val)
	require.Len(t, str, 42)
	assert.Equal(t, "S=", str[:2])
}

func TestNewMPPEKey_PacksLengthAndKey(t *testing.T) {
	salt := [2]byte{0x12, 0x34}
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	attr := NewMPPEKey(salt, 8, key)

	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeMPPEKey, vtype)

	// 2-byte Salt + 1-byte Key-Length + 8-byte Key.
	require.Len(t, val, 11)
	assert.Equal(t, []byte{0x12, 0x34}, val[:2])
	assert.Equal(t, byte(8), val[2])
	assert.Equal(t, key, val[3:])
}

func TestDecode_NonMicrosoftRejected(t *testing.T) {
	// A Cisco VSA must not decode as Microsoft.
	ciscoAttr := vendors.NewVSA(9, 1, []byte("ip:addr=10.0.0.1"))
	_, _, ok := Decode(ciscoAttr)
	assert.False(t, ok)
}

func TestDecode_NonVSARejected(t *testing.T) {
	attr := packet.NewString(1, "alice")
	_, _, ok := Decode(attr)
	assert.False(t, ok)
}

func TestNewMPPESendKey_RoundTrip(t *testing.T) {
	secret := []byte("shared-secret")
	ra := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	key := []byte{
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
	}
	attr, err := NewMPPESendKey(key, ra, secret)
	require.NoError(t, err)

	vtype, val, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeMPPESendKey, vtype, "Vendor-Type 16 (MS-MPPE-Send-Key)")
	require.GreaterOrEqual(t, len(val), 18)
	assert.NotZero(t, val[0]&0x80, "Salt MSB must be set (RFC 2548 §3.3)")

	dec, err := DecryptMPPEKeyAttribute(attr, ra, secret)
	require.NoError(t, err)
	assert.Equal(t, key, dec)
}

func TestNewMPPERecvKey_RoundTrip(t *testing.T) {
	secret := []byte("shared-secret")
	ra := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	key := []byte{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7} // 40-bit
	attr, err := NewMPPERecvKey(key, ra, secret)
	require.NoError(t, err)

	vtype, _, ok := Decode(attr)
	require.True(t, ok)
	assert.Equal(t, VendorTypeMPPERecvKey, vtype, "Vendor-Type 17 (MS-MPPE-Recv-Key)")

	dec, err := DecryptMPPEKeyAttribute(attr, ra, secret)
	require.NoError(t, err)
	assert.Equal(t, key, dec)
}

func TestNewMPPESendKey_DistinctSalts(t *testing.T) {
	secret := []byte("s")
	ra := [16]byte{}
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	a, err := NewMPPESendKey(key, ra, secret)
	require.NoError(t, err)
	b, err := NewMPPESendKey(key, ra, secret)
	require.NoError(t, err)
	_, va, _ := Decode(a)
	_, vb, _ := Decode(b)
	assert.NotEqual(t, va, vb, "random salt must produce distinct VSA values")
}

func TestDecryptMPPEKeyAttribute_RejectsNonMPPEMicrosoft(t *testing.T) {
	secret := []byte("s")
	ra := [16]byte{}
	// MS-CHAP2-Response (type 25) is a Microsoft VSA but not an MPPE-key type.
	attr := NewMSCHAP2Response(make([]byte, 49))
	_, err := DecryptMPPEKeyAttribute(attr, ra, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}

func TestDecryptMPPEKeyAttribute_RejectsNonMicrosoft(t *testing.T) {
	secret := []byte("s")
	ra := [16]byte{}
	// A Cisco VSA with vendor-type 16 must not be treated as MS-MPPE-Send-Key.
	ciscoAttr := vendors.NewVSA(9, 16, []byte("not microsoft"))
	_, err := DecryptMPPEKeyAttribute(ciscoAttr, ra, secret)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}
