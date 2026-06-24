package crypto

import "crypto/md5"

// CHAPPasswordLength is the wire length of a CHAP-Password attribute
// value: 1 byte CHAP-ID plus 16 bytes MD5 hash (RFC 2865 §5.3).
const CHAPPasswordLength = 17

// ComputeCHAPResponse computes the CHAP-Password attribute value for the
// given CHAP-ID, password, and challenge, per RFC 2865 §5.3:
//
//	MD5(chapID || password || challenge)
//
// chapID is a single byte chosen by the client (typically random). The
// challenge is normally the 16-byte Request Authenticator of the
// Access-Request packet, but RFC 2865 §5.40 allows the server to supply a
// longer challenge via the CHAP-Challenge attribute (type 60) instead —
// this function accepts an arbitrary-length challenge for that reason.
//
// The returned slice is 17 bytes: chapID followed by the 16-byte digest.
// It is a fresh allocation; callers may retain it without copying.
func ComputeCHAPResponse(chapID byte, password string, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{chapID})
	h.Write([]byte(password))
	h.Write(challenge)
	out := make([]byte, CHAPPasswordLength)
	out[0] = chapID
	copy(out[1:], h.Sum(nil))
	return out
}

// VerifyCHAPResponse reports whether attr matches the expected CHAP-Password
// value computed from (chapID, password, challenge). attr must be at least
// CHAPPasswordLength bytes; the first byte is treated as the CHAP-ID.
//
// Comparison is constant-time so callers can use this in authentication
// paths without leaking information about the expected digest.
func VerifyCHAPResponse(attr []byte, password string, challenge []byte) bool {
	if len(attr) != CHAPPasswordLength {
		return false
	}
	expected := ComputeCHAPResponse(attr[0], password, challenge)
	return EqualConstantTime(attr[1:], expected[1:])
}
