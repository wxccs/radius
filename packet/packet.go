// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Daniel Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package packet implements the RADIUS packet wire format: the 20-byte header
// (Code, Identifier, Length, Authenticator) followed by a sequence of TLV
// attributes.
//
// A Packet does not hold the shared secret. Callers pass the secret explicitly
// to Marshal and Unmarshal so that authenticator computation, User-Password
// hiding, and Message-Authenticator verification can be performed.
package packet

import (
	"encoding/binary"

	"github.com/wxccs/radius/crypto"
	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

// Packet is a RADIUS protocol data unit. The Authenticator field holds the
// Request Authenticator for request packets (Access-Request, CoA-Request,
// Disconnect-Request) and the Response Authenticator for reply packets.
// For Accounting-Request the field is computed by Marshal and verified by
// Unmarshal; callers do not need to populate it.
type Packet struct {
	Code          types.Code
	Identifier    byte
	Authenticator [16]byte
	Attributes    []Attribute
}

// Marshal serializes the packet to wire format.
//
// The secret is used to:
//   - Encrypt User-Password attributes in Access-Request packets
//     (RFC 2865 §5.2), keyed by the Request Authenticator
//   - Compute the Request Authenticator for Accounting-Request (RFC 2866 §3)
//   - Compute the Response Authenticator for Access-Accept/Reject/Challenge,
//     Accounting-Response, and CoA/DM ACK/NAK packets
//   - Compute Message-Authenticator (RFC 2869 §5.14) when the attribute
//     is present
//
// Returns ErrInvalidCode if Code is not one of the supported values.
func (p *Packet) Marshal(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, radiuserrors.ErrSecretEmpty
	}
	if !isValidCode(p.Code) {
		return nil, radiuserrors.ErrInvalidCode
	}

	attrBytes, msgAuthOffset, err := p.serializeAttributes(secret)
	if err != nil {
		return nil, err
	}

	length := types.PacketMinLength + len(attrBytes)
	if length > maxLengthForCode(p.Code) {
		return nil, radiuserrors.ErrInvalidLength
	}

	out := make([]byte, length)
	out[0] = byte(p.Code)
	out[1] = p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	copy(out[20:], attrBytes)

	// Zero the Message-Authenticator Value so the HMAC can be computed over
	// a packet whose own signature field is zeroed.
	if msgAuthOffset >= 0 {
		valueStart := 20 + msgAuthOffset + 2
		for i := valueStart; i < valueStart+16; i++ {
			out[i] = 0
		}
	}

	// Write the Request Authenticator into the Authenticator field before
	// computing Message-Authenticator (RFC 3579 §3.2). For Access-Request
	// this is the caller-supplied random value (RFC 2865 §3); for reply
	// packets it is the Request Authenticator of the corresponding request,
	// carried in p.Authenticator by the server handler. Accounting-Request,
	// CoA-Request and Disconnect-Request leave the field zero here: their
	// Request Authenticator is derived from the attributes (including the MA
	// Value) and is computed after the MA below, so the MA for those codes
	// is signed over a zero Authenticator field (historic behavior).
	switch p.Code {
	case types.AccessRequest,
		types.AccessAccept, types.AccessReject, types.AccessChallenge,
		types.AccountingResponse,
		types.CoAACK, types.CoANAK, types.DisconnectACK, types.DisconnectNAK:
		copy(out[4:20], p.Authenticator[:])
	}

	// Compute and write Message-Authenticator before the final Authenticator
	// is calculated (RFC 3579 §3.2). The MA Value field was zeroed above.
	if msgAuthOffset >= 0 {
		mac := crypto.ComputeMessageAuthenticator(out, secret)
		valueStart := 20 + msgAuthOffset + 2
		copy(out[valueStart:valueStart+16], mac[:])
	}

	// Compute the final Authenticator. For reply packets this is the Response
	// Authenticator, overwriting the Request Authenticator used as HMAC
	// input above. For Accounting-Request, CoA-Request and Disconnect-Request
	// this is the Request Authenticator (RFC 2866 §3, RFC 5176 §2.3),
	// computed after the MA Value is in place.
	switch p.Code {
	case types.AccountingRequest, types.CoARequest, types.DisconnectRequest:
		auth := crypto.ComputeAccountingRequestAuthenticator(byte(p.Code), p.Identifier, uint16(length), out[20:], secret)
		copy(out[4:20], auth[:])
	case types.AccessAccept, types.AccessReject, types.AccessChallenge,
		types.AccountingResponse,
		types.CoAACK, types.CoANAK, types.DisconnectACK, types.DisconnectNAK:
		auth := crypto.ComputeResponseAuthenticator(byte(p.Code), p.Identifier, uint16(length), p.Authenticator, out[20:], secret)
		copy(out[4:20], auth[:])
	}

	return out, nil
}

// serializeAttributes serializes all attributes into a single byte slice.
// For Access-Request packets, User-Password attributes are encrypted using
// the packet's Request Authenticator and the shared secret. The returned
// msgAuthOffset is the byte offset of the Message-Authenticator attribute
// within the returned slice, or -1 if absent. Multiple Message-Authenticator
// attributes are rejected.
func (p *Packet) serializeAttributes(secret []byte) (attrBytes []byte, msgAuthOffset int, err error) {
	msgAuthOffset = -1
	for _, a := range p.Attributes {
		var ab []byte
		if a.Type == types.AttrUserPassword && p.Code == types.AccessRequest {
			encrypted, encErr := crypto.EncryptUserPassword(a.Value, p.Authenticator, secret)
			if encErr != nil {
				return nil, -1, encErr
			}
			ab, err = Attribute{Type: a.Type, Value: encrypted}.MarshalBinary()
		} else {
			ab, err = a.MarshalBinary()
		}
		if err != nil {
			return nil, -1, err
		}
		if a.Type == types.AttrMessageAuthenticator {
			if msgAuthOffset != -1 {
				return nil, -1, radiuserrors.ErrInvalidAttribute
			}
			msgAuthOffset = len(attrBytes)
		}
		attrBytes = append(attrBytes, ab...)
	}
	return attrBytes, msgAuthOffset, nil
}

// Unmarshal parses a RADIUS packet from data.
//
// The secret is used to verify the Request Authenticator of Accounting-Request
// packets (RFC 2866 §3). For reply packets the caller must separately invoke
// VerifyResponseAuthenticator with the original Request Authenticator, since
// that value is not present in the reply itself. User-Password attributes are
// left encrypted; callers use crypto.DecryptUserPassword to recover the
// plaintext.
//
// Bytes beyond the Length field are treated as padding and ignored. Bytes
// short of the Length field cause ErrShortBuffer.
func (p *Packet) Unmarshal(data []byte, secret []byte) error {
	if len(data) < types.PacketMinLength {
		return radiuserrors.ErrShortBuffer
	}
	code := types.Code(data[0])
	if !isValidCode(code) {
		return radiuserrors.ErrInvalidCode
	}
	id := data[1]
	length := binary.BigEndian.Uint16(data[2:4])
	if int(length) < types.PacketMinLength {
		return radiuserrors.ErrInvalidLength
	}
	if int(length) > maxLengthForCode(code) {
		return radiuserrors.ErrInvalidLength
	}
	if len(data) < int(length) {
		return radiuserrors.ErrShortBuffer
	}

	var auth [16]byte
	copy(auth[:], data[4:20])

	attrData := data[20:length]
	attrs := make([]Attribute, 0)
	for len(attrData) > 0 {
		a, remain, err := UnmarshalAttribute(attrData)
		if err != nil {
			return err
		}
		attrs = append(attrs, a)
		attrData = remain
	}

	p.Code = code
	p.Identifier = id
	p.Authenticator = auth
	p.Attributes = attrs

	// Accounting-Request, CoA-Request, and Disconnect-Request all carry
	// an authenticator computed via the Accounting-Request formula
	// (RFC 2866 §3, RFC 5176 §2.3). We can verify them without external
	// state because the formula does not depend on a prior packet's
	// authenticator.
	if code == types.AccountingRequest ||
		code == types.CoARequest ||
		code == types.DisconnectRequest {
		expected := crypto.ComputeAccountingRequestAuthenticator(byte(code), id, length, data[20:length], secret)
		if !crypto.EqualConstantTime(expected[:], auth[:]) {
			return radiuserrors.ErrAuthenticatorMismatch
		}
	}
	return nil
}

// VerifyResponseAuthenticator checks the Response Authenticator of a reply
// packet against the Request Authenticator of the original request.
//
// rawPacket is the full wire bytes of the reply. Returns ErrAuthenticatorMismatch
// if the digest does not match.
func VerifyResponseAuthenticator(rawPacket []byte, requestAuth [16]byte, secret []byte) error {
	if len(rawPacket) < types.PacketMinLength {
		return radiuserrors.ErrShortBuffer
	}
	code := types.Code(rawPacket[0])
	if !isResponseCode(code) {
		return radiuserrors.ErrInvalidCode
	}
	id := rawPacket[1]
	length := binary.BigEndian.Uint16(rawPacket[2:4])
	if int(length) > len(rawPacket) {
		return radiuserrors.ErrShortBuffer
	}
	var auth [16]byte
	copy(auth[:], rawPacket[4:20])

	expected := crypto.ComputeResponseAuthenticator(byte(code), id, length, requestAuth, rawPacket[20:length], secret)
	if !crypto.EqualConstantTime(expected[:], auth[:]) {
		return radiuserrors.ErrAuthenticatorMismatch
	}
	return nil
}

// VerifyMessageAuthenticator checks the Message-Authenticator attribute
// (RFC 3579 §3.2) carried in rawPacket.
//
// requestAuth is the Request Authenticator of the corresponding request:
//   - For reply packets (Access-Accept/Reject/Challenge, Accounting-Response,
//     CoA/DM ACK/NAK) it is the Request Authenticator of the request this
//     reply corresponds to. The raw packet's Authenticator field holds the
//     Response Authenticator, which is NOT the value used at signing time;
//     requestAuth replaces it in the HMAC input.
//   - For request packets (Access-Request, Accounting-Request, CoA-Request,
//     Disconnect-Request) the raw packet's Authenticator field already
//     holds the Request Authenticator; requestAuth is not used.
//
// The Message-Authenticator Value field is zeroed in a copy of the packet
// before recomputing the HMAC (RFC 2104).
//
// Returns ErrMessageAuthenticatorMissing if the attribute is absent, or
// ErrMessageAuthenticatorMismatch on mismatch.
func VerifyMessageAuthenticator(rawPacket []byte, requestAuth [16]byte, secret []byte) error {
	if len(rawPacket) < types.PacketMinLength {
		return radiuserrors.ErrShortBuffer
	}
	code := types.Code(rawPacket[0])
	length := binary.BigEndian.Uint16(rawPacket[2:4])
	if int(length) > len(rawPacket) {
		return radiuserrors.ErrShortBuffer
	}

	// Locate the Message-Authenticator attribute within the packet body.
	offset := -1
	rest := rawPacket[20:length]
	for len(rest) > 0 {
		startOff := len(rawPacket[20:length]) - len(rest)
		a, remain, err := UnmarshalAttribute(rest)
		if err != nil {
			return err
		}
		if a.Type == types.AttrMessageAuthenticator {
			offset = 20 + startOff
			break
		}
		rest = remain
	}
	if offset < 0 {
		return radiuserrors.ErrMessageAuthenticatorMissing
	}
	if len(rawPacket[offset:]) < 18 {
		return radiuserrors.ErrInvalidAttribute
	}

	// Build a copy of the packet with the Message-Authenticator Value zeroed.
	copyBuf := append([]byte(nil), rawPacket...)
	for i := offset + 2; i < offset+18; i++ {
		copyBuf[i] = 0
	}
	// RFC 3579 §3.2: the MA HMAC covers the Request Authenticator.
	//   - Reply packets: the raw Authenticator field holds the Response
	//     Authenticator; replace it with requestAuth (the Request
	//     Authenticator of the corresponding request).
	//   - Access-Request: the raw Authenticator field already holds the
	//     Request Authenticator; preserve it.
	//   - Accounting-Request, CoA-Request, Disconnect-Request: Marshal
	//     computes the MA with a zero Authenticator field (the Request
	//     Authenticator is written afterwards); zero it here to match.
	//     Full RFC 3579 §3.2 compliance for these request codes (signing
	//     the MA over the Request Authenticator) is not yet implemented.
	switch code {
	case types.AccessRequest:
		// preserve raw Authenticator field
	case types.AccountingRequest, types.CoARequest, types.DisconnectRequest:
		for i := 4; i < 20; i++ {
			copyBuf[i] = 0
		}
	default:
		copy(copyBuf[4:20], requestAuth[:])
	}
	var received [16]byte
	copy(received[:], rawPacket[offset+2:offset+18])

	if !crypto.VerifyMessageAuthenticator(copyBuf, received, secret) {
		return radiuserrors.ErrMessageAuthenticatorMismatch
	}
	return nil
}

// Add appends an attribute to the packet.
func (p *Packet) Add(attr Attribute) {
	p.Attributes = append(p.Attributes, attr)
}

// Get returns all attributes of the given type, in packet order.
func (p *Packet) Get(attrType byte) []Attribute {
	var result []Attribute
	for _, a := range p.Attributes {
		if a.Type == attrType {
			result = append(result, a)
		}
	}
	return result
}

// GetOne returns the first attribute of the given type and true, or false if
// none exists.
func (p *Packet) GetOne(attrType byte) (Attribute, bool) {
	for _, a := range p.Attributes {
		if a.Type == attrType {
			return a, true
		}
	}
	return Attribute{}, false
}

// Set replaces all attributes of the same type as attr with a single
// instance of attr. If no such attribute exists, attr is appended.
func (p *Packet) Set(attr Attribute) {
	found := false
	result := make([]Attribute, 0, len(p.Attributes))
	for _, a := range p.Attributes {
		if a.Type == attr.Type {
			if !found {
				result = append(result, attr)
				found = true
			}
		} else {
			result = append(result, a)
		}
	}
	if !found {
		result = append(result, attr)
	}
	p.Attributes = result
}

// Delete removes all attributes of the given type and returns the count removed.
func (p *Packet) Delete(attrType byte) int {
	count := 0
	result := make([]Attribute, 0, len(p.Attributes))
	for _, a := range p.Attributes {
		if a.Type == attrType {
			count++
		} else {
			result = append(result, a)
		}
	}
	p.Attributes = result
	return count
}

// IsAccess reports whether the packet carries an authentication-family code.
func (p *Packet) IsAccess() bool { return p.Code.IsAccess() }

// IsAccounting reports whether the packet carries an accounting-family code.
func (p *Packet) IsAccounting() bool { return p.Code.IsAccounting() }

// IsCoA reports whether the packet carries a dynamic-authorization code.
func (p *Packet) IsCoA() bool { return p.Code.IsDynamicAuthorization() }

// maxLengthForCode returns the maximum packet length permitted for the code.
// RFC 2866 §3 reduces the limit to 4095 for accounting packets (one byte less
// than the RFC 2865 limit of 4096).
func maxLengthForCode(code types.Code) int {
	if code.IsAccounting() {
		return types.PacketMaxLengthRFC2866
	}
	return types.PacketMaxLengthRFC2865
}

func isValidCode(code types.Code) bool {
	switch code {
	case types.AccessRequest, types.AccessAccept, types.AccessReject, types.AccessChallenge,
		types.AccountingRequest, types.AccountingResponse,
		types.CoARequest, types.CoAACK, types.CoANAK,
		types.DisconnectRequest, types.DisconnectACK, types.DisconnectNAK:
		return true
	}
	return false
}

func isResponseCode(code types.Code) bool {
	switch code {
	case types.AccessAccept, types.AccessReject, types.AccessChallenge,
		types.AccountingResponse,
		types.CoAACK, types.CoANAK, types.DisconnectACK, types.DisconnectNAK:
		return true
	}
	return false
}
