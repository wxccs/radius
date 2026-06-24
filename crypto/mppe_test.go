package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from RFC 3079 §3.5.1 (40-bit) and §3.5.3 (128-bit) sample
// key derivations. The same UserName / Password / challenges feed the
// entire MS-CHAPv2 → MPPE chain, so we exercise the full path here.

// RFC 3079 §3.5.1 sample inputs.
var (
	rfc3079AuthChallenge = [MSCHAPv2ChallengeLength]byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}
	rfc3079PeerChallenge = [MSCHAPv2ChallengeLength]byte{
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
	}
	rfc3079UserName   = "User"
	rfc3079Password   = "clientPass"
	rfc3079NTResponse = [NTResponseLength]byte{
		0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E,
		0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
		0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
	}
	// RFC 3079 §3.5.1 Step 1: NtPasswordHash("clientPass").
	rfc3079PasswordHash = [NTHashLength]byte{
		0x44, 0xEB, 0xBA, 0x8D, 0x53, 0x12, 0xB8, 0xD6,
		0x11, 0x47, 0x44, 0x11, 0xF5, 0x69, 0x89, 0xAE,
	}
	// RFC 3079 §3.5.1 Step 2: MD4(PasswordHash).
	rfc3079PasswordHashHash = [NTHashHashLength]byte{
		0x41, 0xC0, 0x0C, 0x58, 0x4B, 0xD2, 0xD9, 0x1C,
		0x40, 0x17, 0xA2, 0xA1, 0x2F, 0xA5, 0x9F, 0x3F,
	}
	// RFC 3079 §3.5.1 Step 3: GetMasterKey output.
	rfc3079MasterKey = [16]byte{
		0xFD, 0xEC, 0xE3, 0x71, 0x7A, 0x8C, 0x83, 0x8C,
		0xB3, 0x88, 0xE5, 0x27, 0xAE, 0x3C, 0xDD, 0x31,
	}
	// RFC 3079 §3.5.1 Step 4: GetAsymmetricStartKey(..., 8, IsSend=TRUE).
	rfc3079SendStartKey40 = []byte{
		0x8B, 0x7C, 0xDC, 0x14, 0x9B, 0x99, 0x3A, 0x1B,
	}
	// RFC 3079 §3.5.3 Step 3: GetAsymmetricStartKey(..., 16, IsSend=TRUE).
	rfc3079SendStartKey128 = []byte{
		0x8B, 0x7C, 0xDC, 0x14, 0x9B, 0x99, 0x3A, 0x1B,
		0xA1, 0x18, 0xCB, 0x15, 0x3F, 0x56, 0xDC, 0xCB,
	}
)

func TestNtPasswordHash_RFC3079Sample(t *testing.T) {
	got := NtPasswordHash(rfc3079Password)
	assert.Equal(t, rfc3079PasswordHash, got,
		"NtPasswordHash mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(got[:]), hex.EncodeToString(rfc3079PasswordHash[:]))
}

func TestHashNtPasswordHash_RFC3079Sample(t *testing.T) {
	got := HashNtPasswordHash(rfc3079PasswordHash)
	assert.Equal(t, rfc3079PasswordHashHash, got,
		"HashNtPasswordHash mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(got[:]), hex.EncodeToString(rfc3079PasswordHashHash[:]))
}

func TestGenerateNTResponse_RFC3079Sample(t *testing.T) {
	got := GenerateNTResponse(rfc3079AuthChallenge, rfc3079PeerChallenge,
		rfc3079UserName, rfc3079Password)
	assert.Equal(t, rfc3079NTResponse, got,
		"NT-Response mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(got[:]), hex.EncodeToString(rfc3079NTResponse[:]))
}

func TestGetMasterKey_RFC3079Sample(t *testing.T) {
	got := GetMasterKey(rfc3079PasswordHashHash, rfc3079NTResponse)
	assert.Equal(t, rfc3079MasterKey, got,
		"MasterKey mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(got[:]), hex.EncodeToString(rfc3079MasterKey[:]))
}

func TestGetAsymmetricStartKey_40BitSend_RFC3079Sample(t *testing.T) {
	got, err := GetAsymmetricStartKey(rfc3079MasterKey, MPPEKeyLength40Bit, true)
	require.NoError(t, err)
	require.Len(t, got, MPPEKeyLength40Bit)
	assert.Equal(t, rfc3079SendStartKey40, got,
		"SendStartKey40 mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(got), hex.EncodeToString(rfc3079SendStartKey40))
}

func TestGetAsymmetricStartKey_128BitSend_RFC3079Sample(t *testing.T) {
	got, err := GetAsymmetricStartKey(rfc3079MasterKey, MPPEKeyLength128Bit, true)
	require.NoError(t, err)
	require.Len(t, got, MPPEKeyLength128Bit)
	assert.Equal(t, rfc3079SendStartKey128, got,
		"SendStartKey128 mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(got), hex.EncodeToString(rfc3079SendStartKey128))
}

func TestGetAsymmetricStartKey_InvalidLength(t *testing.T) {
	_, err := GetAsymmetricStartKey(rfc3079MasterKey, 0, true)
	assert.Error(t, err, "length 0 must be rejected")
	_, err = GetAsymmetricStartKey(rfc3079MasterKey, 12, true)
	assert.Error(t, err, "length 12 must be rejected")
	_, err = GetAsymmetricStartKey(rfc3079MasterKey, 24, true)
	assert.Error(t, err, "length 24 must be rejected")
}

func TestGetAsymmetricStartKey_SendRecvDiffer(t *testing.T) {
	send, err := GetAsymmetricStartKey(rfc3079MasterKey, MPPEKeyLength40Bit, true)
	require.NoError(t, err)
	recv, err := GetAsymmetricStartKey(rfc3079MasterKey, MPPEKeyLength40Bit, false)
	require.NoError(t, err)
	assert.NotEqual(t, send, recv, "send and recv must use different magics")
}

func TestDeriveMPPEKeysFromPassword_RFC3079Chain(t *testing.T) {
	// Full chain: password + NT-Response → (send40, recv40).
	send, recv, err := DeriveMPPEKeysFromPassword(rfc3079Password,
		rfc3079NTResponse, MPPEKeyLength40Bit)
	require.NoError(t, err)
	require.Len(t, send, MPPEKeyLength40Bit)
	require.Len(t, recv, MPPEKeyLength40Bit)
	assert.Equal(t, rfc3079SendStartKey40, send,
		"send40 mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(send), hex.EncodeToString(rfc3079SendStartKey40))

	// And the 128-bit send key from the same chain.
	send128, _, err := DeriveMPPEKeysFromPassword(rfc3079Password,
		rfc3079NTResponse, MPPEKeyLength128Bit)
	require.NoError(t, err)
	require.Len(t, send128, MPPEKeyLength128Bit)
	assert.Equal(t, rfc3079SendStartKey128, send128,
		"send128 mismatch\n got: %s\nwant: %s",
		hex.EncodeToString(send128), hex.EncodeToString(rfc3079SendStartKey128))
}

func TestDeriveMPPEKeysFromPassword_InvalidLength(t *testing.T) {
	_, _, err := DeriveMPPEKeysFromPassword("pw", rfc3079NTResponse, 7)
	assert.Error(t, err)
}
