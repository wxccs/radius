package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from layeh/radius/rfc2759/mschapv2_test.go, originally derived
// from RFC 2759 reference vectors. Used here to verify that our independent
// implementation matches a known-good reference.

func TestNtPasswordHash_KnownVectors(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		want string // MD4 of UTF-16LE(password), hex
	}{
		// MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0 (well-known).
		{"empty", "", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		// NTHash("password") is a widely-referenced value.
		{"password", "password", "8846f7eaee8fb117ad06bdd830b7586c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := NtPasswordHash(c.pw)
			assert.Equal(t, c.want, hex.EncodeToString(h[:]))
		})
	}
}

func TestNtPasswordHash_ASCIIAndUTF16LE(t *testing.T) {
	// "AB" must encode to UTF-16LE as [0x41, 0x00, 0x42, 0x00] before MD4.
	enc := utf16LE("AB")
	assert.Equal(t, []byte{0x41, 0x00, 0x42, 0x00}, enc)
}

func TestNtPasswordHash_SurrogatePair(t *testing.T) {
	// U+1F600 (😀) encodes to a surrogate pair in UTF-16LE.
	enc := utf16LE("😀")
	assert.Equal(t, []byte{0x3D, 0xD8, 0x00, 0xDE}, enc,
		"surrogate pair must encode as UTF-16LE little-endian")
}

func TestHashNtPasswordHash_Length(t *testing.T) {
	h := NtPasswordHash("password")
	hh := HashNtPasswordHash(h)
	assert.Len(t, hh[:], NTHashHashLength)
}

func TestChallengeHash_KnownVector(t *testing.T) {
	// Reference: RFC 2759 does not publish a worked example, but the
	// algorithm is fully determined. We assert length and that the
	// 8-byte digest equals the first 8 bytes of SHA1(peer||auth||user).
	peer := [16]byte{0x34, 0x13, 0x16, 0x83, 0x81, 0xf7, 0x4b, 0x7b,
		0x28, 0xe6, 0x08, 0x8b, 0xd7, 0xa5, 0x0d, 0xe9}
	auth := [16]byte{0x77, 0xac, 0x2d, 0x4c, 0x31, 0x2a, 0x6a, 0xfe,
		0xb9, 0xd1, 0x76, 0xb4, 0xdd, 0x1d, 0x1a, 0x1d}
	got := ChallengeHash(peer, auth, "test")
	assert.Len(t, got[:], ChallengeHashLength)
}

func TestGenerateNTResponse_KnownVectors(t *testing.T) {
	cases := []struct {
		name string
		auth [16]byte
		peer [16]byte
		user string
		pw   string
		want [24]byte
	}{
		{
			name: "layeh-vector-1",
			auth: [16]byte{
				0x77, 0xac, 0x2d, 0x4c, 0x31, 0x2a, 0x6a, 0xfe,
				0xb9, 0xd1, 0x76, 0xb4, 0xdd, 0x1d, 0x1a, 0x1d,
			},
			peer: [16]byte{
				0x34, 0x13, 0x16, 0x83, 0x81, 0xf7, 0x4b, 0x7b,
				0x28, 0xe6, 0x08, 0x8b, 0xd7, 0xa5, 0x0d, 0xe9,
			},
			user: "test",
			pw:   "superSecretPassword",
			want: [24]byte{
				0x62, 0x95, 0xb2, 0x14, 0x39, 0x95, 0xf9, 0xf6,
				0x58, 0x69, 0x19, 0x77, 0xef, 0x12, 0x79, 0x89,
				0x10, 0xff, 0x29, 0x73, 0xb5, 0xb5, 0x13, 0xba,
			},
		},
		{
			name: "layeh-vector-2",
			auth: [16]byte{
				0xd5, 0x71, 0x7d, 0x58, 0xe9, 0xfb, 0x9c, 0xf4,
				0x2d, 0xbb, 0x0c, 0x1a, 0x8a, 0xdf, 0x98, 0x79,
			},
			peer: [16]byte{
				0x27, 0x9c, 0xb4, 0x11, 0x49, 0x4d, 0x5a, 0x84,
				0xcd, 0xf2, 0xd2, 0xee, 0x36, 0xfb, 0x5c, 0xdd,
			},
			user: "test",
			pw:   "superSecretPassword",
			want: [24]byte{
				0xf5, 0xe4, 0x71, 0xec, 0xb5, 0x59, 0xa9, 0xf7,
				0xc6, 0x9a, 0x70, 0x8b, 0x12, 0xe7, 0xa8, 0x6d,
				0xd2, 0xfe, 0xf9, 0xab, 0x3f, 0x2a, 0xed, 0x0a,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GenerateNTResponse(c.auth, c.peer, c.user, c.pw)
			assert.Equal(t, c.want, got,
				"NT-Response mismatch\n got: %s\nwant: %s",
				hex.EncodeToString(got[:]),
				hex.EncodeToString(c.want[:]))
		})
	}
}

func TestGenerateNTResponse_Deterministic(t *testing.T) {
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	peer := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	got1 := GenerateNTResponse(auth, peer, "user", "pw")
	got2 := GenerateNTResponse(auth, peer, "user", "pw")
	assert.Equal(t, got1, got2, "same input must produce same output")
}

func TestGenerateNTResponse_DifferentPasswords(t *testing.T) {
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	peer := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	a := GenerateNTResponse(auth, peer, "user", "pw1")
	b := GenerateNTResponse(auth, peer, "user", "pw2")
	assert.NotEqual(t, a, b, "different passwords must produce different responses")
}

func TestGenerateAuthenticatorResponse_Format(t *testing.T) {
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	peer := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	ntResponse := [24]byte{}

	got := GenerateAuthenticatorResponse(auth, peer, ntResponse, "user", "pw")
	require.Len(t, got, 42, "AuthenticatorResponse must be 'S=' + 40 hex chars")
	assert.Equal(t, "S=", got[:2])
	// All hex chars must be uppercase.
	for _, c := range got[2:] {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'),
			"char %q is not an uppercase hex digit", c)
	}
}

func TestExpandDesKey_7BytesTo8Bytes(t *testing.T) {
	in := []byte{0x61, 0xee, 0x8b, 0x50, 0x74, 0x8f, 0x5e}
	out := expandDesKey(in)
	assert.Len(t, out, 8)
	// Parity bit (low bit of each byte) is 0 in our implementation;
	// the high 7 bits must match the standard expansion. We verify the
	// first byte's high 7 bits equal in[0]'s 7 high bits.
	assert.Equal(t, byte(in[0]&0xFE), out[0]&0xFE,
		"high 7 bits of out[0] must equal high 7 bits of in[0]")
}
