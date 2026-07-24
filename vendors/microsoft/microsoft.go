// Package microsoft implements Vendor-Specific attributes for
// Microsoft (SMI Network Management Private Enterprise Code 311).
//
// Microsoft VSAs use the RFC 2865 §5.26 layout
// (Vendor-Id | Vendor-Type | Vendor-Length | Value). The package covers
// three attribute sources, split across two files:
//
//   - microsoft.go: the MS-CHAPv2 / MPPE attributes defined by RFC 2548
//     (Vendor-Type 1-27), with typed constructors and the MPPE
//     key-derivation helpers from the crypto package wired into the
//     wire-level packet format.
//   - rnas.go: the NAP / NPAS attributes defined by the Microsoft Open
//     Specifications [MS-RNAP] (Vendor-Type 0x22-0x3F) and [MS-RNAS]
//     (adds 0x41), plus the SSTP vendor-specific value for the standard
//     Tunnel-Type (Type 64) attribute.
//
// All Microsoft VSAs share Vendor-Id 311 and decode through the
// package-level Decode helper.
package microsoft

import (
	"github.com/wxccs/radius/v2/crypto"
	radiuserrors "github.com/wxccs/radius/v2/errors"
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Microsoft's SMI Network Management Private Enterprise
// Code, as registered with IANA. Used as the 4-byte Vendor-Id prefix
// on every Microsoft VSA.
const VendorID uint32 = 311

// Microsoft VSA sub-type numbers from RFC 2548 §2.
const (
	// VendorTypeMSCHAPResponse is the MS-CHAP-Response VSA (RFC 2548 §2.2).
	// Carries the legacy MS-CHAPv1 response.
	VendorTypeMSCHAPResponse byte = 1
	// VendorTypeMSCHAPError is the MS-CHAP-Error VSA (RFC 2548 §2.3).
	VendorTypeMSCHAPError byte = 2
	// VendorTypeMSCHAPCPW1 is the MS-CHAP-CPW-1 VSA (RFC 2548 §2.4),
	// carrying a password change request in MS-CHAPv1 form.
	VendorTypeMSCHAPCPW1 byte = 3
	// VendorTypeMSCHAPCPW2 is the MS-CHAP-CPW-2 VSA (RFC 2548 §2.5).
	VendorTypeMSCHAPCPW2 byte = 4
	// VendorTypeMSCHAPLMResponse is the MS-CHAP-LM-Response VSA
	// (RFC 2548 §2.6), carrying the LM-encoded response.
	VendorTypeMSCHAPLMResponse byte = 5
	// VendorTypeMSCHAP2Response is the MS-CHAP2-Response VSA
	// (RFC 2548 §2.7.1), carrying the 49-byte MS-CHAPv2 response
	// observed during MS-CHAPv2 authentication.
	VendorTypeMSCHAP2Response byte = 25
	// VendorTypeMSCHAP2Success is the MS-CHAP2-Success VSA
	// (RFC 2548 §2.7.2). Carries the "S=" success message.
	VendorTypeMSCHAP2Success byte = 26
	// VendorTypeMSCHAP2CPW is the MS-CHAP2-CPW VSA (RFC 2548 §2.7.3),
	// carrying an MS-CHAPv2 password change request.
	VendorTypeMSCHAP2CPW byte = 27
	// VendorTypeMPEGKey is the MPPE-Key VSA used to transport
	// session keys. The MPPE sub-types use this single type with
	// separate sub-encodings for send/recv and 40/56/128-bit lengths.
	VendorTypeMPPEKey byte = 12
	// VendorTypeMPPESendKey is the MS-MPPE-Send-Key VSA (RFC 2548
	// §2.4.2). Carries the server->client MPPE session key, encrypted
	// per RFC 2548 §3.3.
	VendorTypeMPPESendKey byte = 16
	// VendorTypeMPPERecvKey is the MS-MPPE-Recv-Key VSA (RFC 2548
	// §2.4.3). Carries the client->server MPPE session key, encrypted
	// per RFC 2548 §3.3.
	VendorTypeMPPERecvKey byte = 17
)

// NewMSCHAPResponse constructs an MS-CHAP-Response VSA carrying the
// given raw bytes (the 49-byte MS-CHAPv1 response).
func NewMSCHAPResponse(value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeMSCHAPResponse, value)
}

// NewMSCHAP2Response constructs an MS-CHAP2-Response VSA carrying the
// given raw bytes (the 49-byte MS-CHAPv2 response: 1-byte Ident +
// 16-byte Peer-Challenge + 8-byte Reserved + 24-byte NT-Response).
func NewMSCHAP2Response(value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeMSCHAP2Response, value)
}

// NewMSCHAP2Success constructs an MS-CHAP2-Success VSA carrying the
// Authenticator Response string returned by GenerateAuthenticatorResponse.
// The string is "S=" + 40 hex chars, but the VSA value is exactly the
// response string with no length prefix.
func NewMSCHAP2Success(authenticatorResponse string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeMSCHAP2Success, []byte(authenticatorResponse))
}

// NewMSCHAP2SuccessFromAuth constructs an MS-CHAP2-Success VSA from
// the MS-CHAPv2 input parameters by computing the Authenticator
// Response via crypto.GenerateAuthenticatorResponse. Convenience for
// RADIUS servers that have just authenticated a user and need to
// return the success response to the NAS.
func NewMSCHAP2SuccessFromAuth(authChallenge, peerChallenge [crypto.MSCHAPv2ChallengeLength]byte, ntResponse [crypto.NTResponseLength]byte, userName, password string) packet.Attribute {
	resp := crypto.GenerateAuthenticatorResponse(authChallenge, peerChallenge, ntResponse, userName, password)
	return NewMSCHAP2Success(resp)
}

// NewMPPEKey constructs an MS-MPPE-* VSA carrying an MPPE session key.
//
// RFC 2548 §2.11 wraps MPPE session keys in a 36-byte (40-bit key) or
// 40-byte (128-bit key) value consisting of:
//
//   - 2-byte Salt
//   - 1-byte Key-Length (8 or 16)
//   - N-byte Plaintext Key (8 or 16)
//   - Padding to fill the VSA Value field to 36/40 bytes
//   - The key is encrypted with the shared secret using the SHA-1
//   - RC4-based algorithm defined in RFC 2548 §3.3.
//
// This helper does NOT implement the encryption step; it packs the
// plaintext Key-Length + Key into a 36-byte buffer suitable for
// encryption by the caller. Implementing the full RFC 2548 §3.3
// encryption is left to a future helper that takes a shared secret.
func NewMPPEKey(salt [2]byte, keyLength byte, key []byte) packet.Attribute {
	// 2-byte Salt + 1-byte Key-Length + N-byte Key, with the VSA
	// Value padded out to either 36 or 40 bytes (RFC 2548 §3.3
	// specifies 36 bytes for 40-bit keys and 40 bytes for 128-bit
	// keys; we accept any length and let the caller pick the padding
	// policy).
	totalLen := 3 + len(key)
	v := make([]byte, totalLen)
	v[0] = salt[0]
	v[1] = salt[1]
	v[2] = keyLength
	copy(v[3:], key)
	return vendors.NewVSA(VendorID, VendorTypeMPPEKey, v)
}

// NewMPPESendKey constructs an MS-MPPE-Send-Key VSA (Vendor-Type 16, RFC 2548
// §2.4.2) carrying the server->client MPPE session key. The key is encrypted
// per RFC 2548 §3.3 using the shared secret and the Access-Request's Request
// Authenticator.
//
// key is the raw session key (typically 8 octets for 40-bit MPPE, 16 for
// 128-bit). requestAuth is the Request Authenticator of the enclosing
// Access-Request.
func NewMPPESendKey(key []byte, requestAuth [16]byte, secret []byte) (packet.Attribute, error) {
	enc, err := crypto.EncryptMPPEKey(key, requestAuth, secret)
	if err != nil {
		return packet.Attribute{}, err
	}
	return vendors.NewVSA(VendorID, VendorTypeMPPESendKey, enc), nil
}

// NewMPPERecvKey constructs an MS-MPPE-Recv-Key VSA (Vendor-Type 17, RFC 2548
// §2.4.3) carrying the client->server MPPE session key, encrypted per RFC
// 2548 §3.3.
func NewMPPERecvKey(key []byte, requestAuth [16]byte, secret []byte) (packet.Attribute, error) {
	enc, err := crypto.EncryptMPPEKey(key, requestAuth, secret)
	if err != nil {
		return packet.Attribute{}, err
	}
	return vendors.NewVSA(VendorID, VendorTypeMPPERecvKey, enc), nil
}

// DecryptMPPEKeyAttribute decrypts an MS-MPPE-Send-Key (Vendor-Type 16) or
// MS-MPPE-Recv-Key (Vendor-Type 17) VSA and returns the session key.
// requestAuth is the Request Authenticator of the Access-Request that
// produced the enclosing Access-Accept. Returns ErrInvalidAttribute if attr
// is not a Microsoft VSA of one of these two types.
func DecryptMPPEKeyAttribute(attr packet.Attribute, requestAuth [16]byte, secret []byte) ([]byte, error) {
	vendorType, value, ok := Decode(attr)
	if !ok || (vendorType != VendorTypeMPPESendKey && vendorType != VendorTypeMPPERecvKey) {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	return crypto.DecryptMPPEKey(value, requestAuth, secret)
}

// Decode returns the vendor-type and value if attr is a Microsoft VSA.
// Returns ok=false if attr is not a Microsoft VSA (wrong Vendor-Id or
// not a VSA at all).
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
