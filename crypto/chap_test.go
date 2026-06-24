package crypto

import (
	"crypto/md5"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 2865 §5.3 does not give a worked CHAP example, but the algorithm is
// fully specified. We cross-check our implementation against a hand-rolled
// MD5 invocation to catch transcription errors.
func TestComputeCHAPResponse_Algorithm(t *testing.T) {
	chapID := byte(0x42)
	password := "alice-secret"
	challenge := []byte("0123456789ABCDEF")[:16]

	got := ComputeCHAPResponse(chapID, password, challenge)
	require.Len(t, got, CHAPPasswordLength)
	assert.Equal(t, chapID, got[0])

	h := md5.New()
	h.Write([]byte{chapID})
	h.Write([]byte(password))
	h.Write(challenge)
	wantDigest := h.Sum(nil)
	assert.Equal(t, wantDigest, got[1:])
}

func TestComputeCHAPResponse_IndependentOfCallerBuffer(t *testing.T) {
	challenge := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	got := ComputeCHAPResponse(1, "pw", challenge)
	challenge[0] = 0x00 // mutate caller buffer; result must not change
	got2 := ComputeCHAPResponse(1, "pw", []byte{0xAA, 0xBB, 0xCC, 0xDD})
	assert.Equal(t, got, got2)
}

func TestVerifyCHAPResponse_Match(t *testing.T) {
	chapID := byte(7)
	password := "hunter2"
	challenge := make([]byte, 16)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	attr := ComputeCHAPResponse(chapID, password, challenge)
	assert.True(t, VerifyCHAPResponse(attr, password, challenge))
}

func TestVerifyCHAPResponse_WrongPassword(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	attr := ComputeCHAPResponse(7, "hunter2", challenge)
	assert.False(t, VerifyCHAPResponse(attr, "wrong-password", challenge))
}

func TestVerifyCHAPResponse_WrongLength(t *testing.T) {
	assert.False(t, VerifyCHAPResponse([]byte{0x01}, "pw", []byte{0x02}))
	assert.False(t, VerifyCHAPResponse(make([]byte, 17+1), "pw", []byte{0x02}))
}
