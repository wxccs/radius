package crypto

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"

	radiuserrors "github.com/wxccs/radius/v2/errors"
)

// MPPE key lengths supported by GetAsymmetricStartKey (RFC 3079 §3.3).
const (
	// MPPEKeyLength40Bit produces an 8-byte session key. The 40 in the
	// name refers to the usable key bits: the remaining 24 bits are
	// fixed and known, so 40-bit MPPE is weak and only used for legacy
	// compatibility.
	MPPEKeyLength40Bit = 8
	// MPPEKeyLength128Bit produces a 16-byte session key, the strongest
	// mode supported by MPPE.
	MPPEKeyLength128Bit = 16
)

// mppePad1 and mppePad2 are the 40-byte SHA-1 padding constants from
// RFC 3079 §3.4.
var (
	mppePad1 = [40]byte{}
	mppePad2 = [40]byte{
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
	}

	// mppeMagic1/2/3 are the magic constants from RFC 3079 §3.4.
	// magic1 selects the master key derivation. magic2/3 select the
	// per-direction session key: magic2 is the client→server direction
	// (client send / server receive); magic3 is the server→client
	// direction (server send / client receive). Our GetAsymmetricStartKey
	// takes the server's perspective, so isSend=true uses magic3.
	mppeMagic1 = []byte{
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
		0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79,
	}
	mppeMagic2 = []byte{
		0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
		0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
		0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
		0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
		0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
		0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6b, 0x65, 0x79, 0x2e,
	}
	mppeMagic3 = []byte{
		0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
		0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
		0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
		0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
		0x6b, 0x65, 0x79, 0x2e,
	}
)

// GetMasterKey derives the 16-byte MPPE master key from the password hash
// hash and the NT-Response of an MS-CHAPv2 exchange (RFC 3079 §3.4):
//
//	SHA1(passwordHashHash || ntResponse || magic1)[:16]
//
// The master key is then used to derive per-direction session keys via
// GetAsymmetricStartKey.
func GetMasterKey(passwordHashHash [NTHashHashLength]byte, ntResponse [NTResponseLength]byte) [16]byte {
	h := sha1.New()
	h.Write(passwordHashHash[:])
	h.Write(ntResponse[:])
	h.Write(mppeMagic1)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// GetAsymmetricStartKey derives a per-direction session key from the MPPE
// master key (RFC 3079 §3.4):
//
//	SHA1(masterKey || pad1 || magic || pad2)[:sessionKeyLength]
//
// isSend is interpreted from the server's perspective, matching the sample
// call in RFC 3079 §3.3 (IsSend=TRUE, IsServer=TRUE → magic3). Therefore:
//   - isSend=true  → magic3 (server→client direction; the value to place
//     in the MS-MPPE-Send-Key attribute returned by a RADIUS server)
//   - isSend=false → magic2 (client→server direction; the value to place
//     in the MS-MPPE-Recv-Key attribute returned by a RADIUS server)
//
// sessionKeyLength must be MPPEKeyLength40Bit (8) or MPPEKeyLength128Bit
// (16); other values return ErrInvalidLength.
func GetAsymmetricStartKey(masterKey [16]byte, sessionKeyLength int, isSend bool) ([]byte, error) {
	if sessionKeyLength != MPPEKeyLength40Bit && sessionKeyLength != MPPEKeyLength128Bit {
		return nil, fmt.Errorf("%w: MPPE session key length must be %d or %d, got %d",
			radiuserrors.ErrInvalidLength, MPPEKeyLength40Bit, MPPEKeyLength128Bit, sessionKeyLength)
	}
	h := sha1.New()
	h.Write(masterKey[:])
	h.Write(mppePad1[:])
	if isSend {
		h.Write(mppeMagic3)
	} else {
		h.Write(mppeMagic2)
	}
	h.Write(mppePad2[:])
	out := make([]byte, sessionKeyLength)
	copy(out, h.Sum(nil))
	return out, nil
}

// DeriveMPPEKeysFromPassword is a convenience wrapper that performs the
// full MS-CHAPv2 → MPPE derivation chain:
//
//  1. NtPasswordHash(password)
//  2. HashNtPasswordHash(NtPasswordHash(password))
//  3. GetMasterKey(hashHash, ntResponse)
//  4. GetAsymmetricStartKey(masterKey, sessionKeyLength, isSend)
//
// Returns the server-perspective send and receive session keys (both
// sessionKeyLength bytes): send encrypts server→client traffic (and goes
// in MS-MPPE-Send-Key), recv encrypts client→server traffic (and goes in
// MS-MPPE-Recv-Key). Callers performing only one side can ignore the
// unneeded return value.
func DeriveMPPEKeysFromPassword(password string, ntResponse [NTResponseLength]byte, sessionKeyLength int) (send, recv []byte, err error) {
	ntHash := NtPasswordHash(password)
	hashHash := HashNtPasswordHash(ntHash)
	master := GetMasterKey(hashHash, ntResponse)
	send, err = GetAsymmetricStartKey(master, sessionKeyLength, true)
	if err != nil {
		return nil, nil, err
	}
	recv, err = GetAsymmetricStartKey(master, sessionKeyLength, false)
	if err != nil {
		return nil, nil, err
	}
	return send, recv, nil
}

// mppeKeyMaxLen is the maximum key length transportable in a single
// MS-MPPE-Send-Key / MS-MPPE-Recv-Key attribute (RFC 2548 §3.3). The
// attribute Value is at most 253 octets; minus the 2-byte Salt leaves 251
// octets of ciphertext, a multiple of 16 so at most 240; minus the 1-byte
// Key-Length leaves 239 octets for the key.
const mppeKeyMaxLen = 239

// EncryptMPPEKey encrypts an MPPE session key per RFC 2548 §3.3 for transport
// in an MS-MPPE-Send-Key (Vendor-Type 16) or MS-MPPE-Recv-Key (Vendor-Type 17)
// attribute. The wire algorithm is identical to Tunnel-Password (RFC 2868
// §3.5): salted MD5-feedback over a length-prefixed plaintext.
//
// requestAuth is the 16-byte Request Authenticator of the enclosing
// Access-Request. Returns the VSA Value (Salt + encrypted String).
func EncryptMPPEKey(key []byte, requestAuth [16]byte, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, radiuserrors.ErrSecretEmpty
	}
	if len(key) > mppeKeyMaxLen {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	salt := make([]byte, 2)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	salt[0] |= 0x80 // RFC 2548 §3.3: the MSB of Salt MUST be set.
	return encryptSaltedPassword(key, requestAuth, secret, salt), nil
}

// DecryptMPPEKey reverses EncryptMPPEKey. value is the MS-MPPE-Send-Key /
// MS-MPPE-Recv-Key attribute Value (Salt + encrypted String). requestAuth is
// the Request Authenticator of the enclosing Access-Request. Returns the key
// scoped by the Key-Length field; any padding is discarded.
//
// Per RFC 2548 §3.3 Implementation Notes, the returned key may be longer than
// the encryption scheme in use requires; callers are responsible for any
// truncation.
func DecryptMPPEKey(value []byte, requestAuth [16]byte, secret []byte) ([]byte, error) {
	return decryptSaltedAttribute(value, requestAuth, secret)
}
