package crypto

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"strings"

	// MD4 is required by RFC 2759 §8.3 for the NT password hash used
	// in MS-CHAPv2. The algorithm is cryptographically broken for
	// general-purpose use but mandated by the protocol; we use it
	// solely for legacy MS-CHAPv2 compatibility, not for new security.
	"golang.org/x/crypto/md4" //nolint:staticcheck
)

// MS-CHAPv2 / MS-CHAPv1 constants from RFC 2759 and RFC 3079.
const (
	// NTHashLength is the length of an NT password hash: MD4 over the
	// UTF-16LE encoding of the password (RFC 2759 §8.3).
	NTHashLength = 16
	// NTHashHashLength is the length of the MD4 over the NT hash
	// (RFC 2759 §8.4): another 16 bytes.
	NTHashHashLength = 16
	// NTResponseLength is the length of the MS-CHAPv2 NT-Response field
	// (RFC 2759 §8.7): 24 bytes.
	NTResponseLength = 24
	// MSCHAPv2ChallengeLength is the length of the Authenticator
	// Challenge or Peer Challenge used by MS-CHAPv2 (RFC 2759 §8.6).
	MSCHAPv2ChallengeLength = 16
	// ChallengeHashLength is the 8-byte output of ChallengeHash
	// (RFC 2759 §8.6).
	ChallengeHashLength = 8
	// AuthenticatorResponseLength is the length of the S=... response
	// string produced by GenerateAuthenticatorResponse (RFC 2759 §8.7).
	AuthenticatorResponseLength = 42
)

// NtPasswordHash returns the NT hash of password: MD4 over the UTF-16LE
// encoding of password (RFC 2759 §8.3). The password is encoded to
// UTF-16LE without a BOM; any byte order mark in the input string is
// treated as part of the password.
//
// Returned as a fixed-size array so callers can use it directly in
// downstream operations (HashNtPasswordHash, GenerateNTResponse).
func NtPasswordHash(password string) [NTHashLength]byte {
	enc := utf16LE(password)
	h := md4.New()
	h.Write(enc)
	var out [NTHashLength]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashNtPasswordHash returns the MD4 hash of an NT password hash
// (RFC 2759 §8.4). This is the "password hash hash" used as input to
// GenerateAuthenticatorResponse and to MPPE key derivation.
func HashNtPasswordHash(ntHash [NTHashLength]byte) [NTHashHashLength]byte {
	h := md4.New()
	h.Write(ntHash[:])
	var out [NTHashHashLength]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ChallengeHash implements RFC 2759 §8.6:
//
//	SHA1(peerChallenge + authenticatorChallenge + userName)[:8]
//
// userName is the raw byte form supplied by the caller; the RFC specifies
// the user name with no domain prefix when a "DOMAIN\user" form is in
// use. Callers should strip the domain before calling this function.
func ChallengeHash(peerChallenge, authenticatorChallenge [MSCHAPv2ChallengeLength]byte, userName string) [ChallengeHashLength]byte {
	h := sha1.New()
	h.Write(peerChallenge[:])
	h.Write(authenticatorChallenge[:])
	h.Write([]byte(userName))
	var out [ChallengeHashLength]byte
	copy(out[:], h.Sum(nil))
	return out
}

// GenerateNTResponse implements RFC 2759 §8.7:
//
//	DesEncrypt(7 copies of NtPasswordHash[0..7] + Z1, ZPasswordHash[0..7])
//	DesEncrypt(...)
//	... 3 blocks ...
//	Concatenated: 24-byte NT-Response
//
// Specifically:
//
//	ZPasswordHash = NtPasswordHash(password)
//	ZPasswordHashHash = HashNtPasswordHash(ZPasswordHash)
//	Challenge = ChallengeHash(peerChallenge, authChallenge, userName)
//	NTResponse = Concat(DesEncrypt(ZPasswordHash[0..7] repeated to 8 bytes,
//	    Challenge[0..7]), DesEncrypt(ZPasswordHash[0..7], Challenge[8..15]),
//	    DesEncrypt(ZPasswordHash[0..7], Challenge[0..7] (truncated)))
//
// The three DES keys are derived by repeating the 7-byte NT hash to fill
// 8 bytes (with bit-reversal parity applied by the DES implementation
// itself, which we replicate here because Go's crypto/des requires 8-byte
// keys with valid parity bits — they are ignored in operation but must
// be present).
func GenerateNTResponse(authenticatorChallenge, peerChallenge [MSCHAPv2ChallengeLength]byte, userName, password string) [NTResponseLength]byte {
	ntHash := NtPasswordHash(password)
	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, userName)
	return desEncryptNTResponse(ntHash, challenge)
}

// GenerateAuthenticatorResponse implements RFC 2759 §8.7. It derives the
// 42-octet "S=<40 hex>" Authenticator Response string that the server
// compares against the MS-CHAP2-Response attribute's Authenticator Response
// field.
//
//	digest1  = SHA1(NTHashHash || NTResponse || Magic1)
//	challenge = ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName)
//	final    = SHA1(digest1 || challenge || Magic2)
//	AuthenticatorResponse = "S=" + uppercase_hex(final)
//
// Magic1 (39 octets, "Magic server to client signing constant") selects the
// password-hash-hash digest; Magic2 (41 octets, "Pad to make it do more than
// one iteration") binds the 8-byte challenge. This matches FreeRADIUS
// mschap_auth_response() in src/modules/rlm_mschap/mschap.c.
func GenerateAuthenticatorResponse(authenticatorChallenge, peerChallenge [MSCHAPv2ChallengeLength]byte, ntResponse [NTResponseLength]byte, userName, password string) string {
	ntHash := NtPasswordHash(password)
	ntHashHash := HashNtPasswordHash(ntHash)

	// Magic1: SHA1(NTHashHash || NTResponse || Magic1)
	h1 := sha1.New()
	h1.Write(ntHashHash[:])
	h1.Write(ntResponse[:])
	h1.Write(mschapv2Magic1)
	digest1 := h1.Sum(nil)

	// Challenge = ChallengeHash(peerChallenge, authenticatorChallenge, userName)
	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, userName)

	// Final: SHA1(digest1 || challenge || Magic2)
	hf := sha1.New()
	hf.Write(digest1)
	hf.Write(challenge[:])
	hf.Write(mschapv2Magic2)
	final := hf.Sum(nil)

	return "S=" + hexUpper(final)
}

// mschapv2Magic1/2 are the constants from RFC 2759 §8.7 used by
// GenerateAuthenticatorResponse.
var (
	mschapv2Magic1 = []byte{
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
		0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
		0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
	}
	mschapv2Magic2 = []byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
		0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
		0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E,
	}
)

// desEncryptNTResponse expands the 7-byte NT hash into three DES keys
// and encrypts the three 8-byte challenge blocks, concatenating the
// result. RFC 2759 §8.7.
func desEncryptNTResponse(ntHash [NTHashLength]byte, challenge [ChallengeHashLength]byte) [NTResponseLength]byte {
	var out [NTResponseLength]byte
	// The three 7-byte DES key inputs are slices of the 16-byte NT hash,
	// zero-padded for the third block when the hash runs out.
	key1 := expandDesKey(ntHash[0:7])
	key2 := expandDesKey(ntHash[7:14])
	key3 := expandDesKey([]byte{ntHash[14], ntHash[15], 0, 0, 0, 0, 0})
	// RFC 2759 §8.7: each block encrypts the same 8-byte challenge.
	block := challenge[0:8]
	encryptBlock(key1, block, out[0:8])
	encryptBlock(key2, block, out[8:16])
	encryptBlock(key3, block, out[16:24])
	return out
}

// encryptBlock encrypts 8 bytes of plaintext with DES under the given
// 8-byte key, writing the result into dst. Panics on error because the
// only failure mode is invalid key length, which we control via callers.
func encryptBlock(key, plaintext, dst []byte) {
	c, err := des.NewCipher(key)
	if err != nil {
		panic("crypto: mschapv2 DES cipher: " + err.Error())
	}
	c.Encrypt(dst, plaintext)
}

// expandDesKey expands a 7-byte key into an 8-byte key by inserting a
// parity bit in the low bit of each byte, per the MS-CHAP / MS-CHAPv2
// key expansion algorithm. The high 7 bits of each output byte come from
// the 7 input bytes; the low bit is a parity bit (we set it to 0 since
// DES ignores it for encryption — parity is checked only by hardware
// implementations).
func expandDesKey(key7 []byte) []byte {
	if len(key7) != 7 {
		panic("crypto: expandDesKey requires 7-byte input")
	}
	out := make([]byte, 8)
	// Standard 7-byte → 8-byte expansion: bit-pack 56 bits into 8 bytes
	// with each output byte holding 7 high bits and 1 low parity bit.
	out[0] = key7[0] >> 1
	out[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
	out[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
	out[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
	out[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
	out[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
	out[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
	out[7] = key7[6] & 0x7F
	// Shift each byte left by 1 to occupy the high 7 bits, leaving the
	// low bit as 0 (parity placeholder).
	for i := range out {
		out[i] <<= 1
	}
	return out
}

// utf16LE encodes s as UTF-16 little-endian without a BOM. Used by
// NtPasswordHash to match the RFC 2759 §8.3 password encoding.
func utf16LE(s string) []byte {
	r := []rune(s)
	buf := make([]byte, 0, len(r)*2)
	for _, c := range r {
		// Encode the rune as UTF-16 in surrogate pairs when needed.
		if c <= 0xFFFF {
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], uint16(c))
			buf = append(buf, b[:]...)
		} else {
			c -= 0x10000
			hi := 0xD800 + (c >> 10)
			lo := 0xDC00 + (c & 0x3FF)
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], uint16(hi))
			buf = append(buf, b[:]...)
			binary.LittleEndian.PutUint16(b[:], uint16(lo))
			buf = append(buf, b[:]...)
		}
	}
	return buf
}

// hexUpper returns the uppercase hex string of b. We avoid encoding/hex
// to keep the dependency surface minimal and because the call is in a
// hot path only during AuthenticatorResponse generation.
func hexUpper(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0F]
	}
	return string(out)
}

// stripDomain removes the "DOMAIN\" prefix from a user name, returning the
// bare account name. Used by MS-CHAPv2 callers who receive a fully
// qualified user name from the NAS.
func stripDomain(user string) string {
	if _, after, ok := strings.Cut(user, "\\"); ok {
		return after
	}
	return user
}

// _ = stripDomain keeps the import alive in case callers want to expose
// it later; for now it's an internal helper kept for future use.
var _ = stripDomain
