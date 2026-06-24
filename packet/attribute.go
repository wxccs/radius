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

package packet

import (
	"encoding/binary"
	"net"

	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

// Attribute is a single RADIUS TLV: a 1-byte Type, a 1-byte Length covering
// Type+Length+Value (so 2..255), and up to 253 bytes of Value. The Value
// slice is always a private copy; mutating it does not affect any packet the
// attribute was decoded from.
type Attribute struct {
	Type  byte
	Value []byte
}

// MarshalBinary encodes the attribute as Type + Length + Value in network
// byte order. Returns ErrAttributeTooLong if Value exceeds 253 octets.
func (a Attribute) MarshalBinary() ([]byte, error) {
	if len(a.Value) > types.AttrValueMaxLength {
		return nil, radiuserrors.ErrAttributeTooLong
	}
	out := make([]byte, 2+len(a.Value))
	out[0] = a.Type
	out[1] = byte(2 + len(a.Value))
	copy(out[2:], a.Value)
	return out, nil
}

// UnmarshalAttribute decodes a single attribute from the start of data and
// returns the decoded attribute alongside the remaining bytes. The Value
// slice is a copy, safe to retain without copying.
func UnmarshalAttribute(data []byte) (Attribute, []byte, error) {
	if len(data) < 2 {
		return Attribute{}, nil, radiuserrors.ErrShortBuffer
	}
	attrType := data[0]
	attrLen := data[1]
	if attrLen < 2 {
		return Attribute{}, nil, radiuserrors.ErrInvalidAttribute
	}
	if int(attrLen) > len(data) {
		return Attribute{}, nil, radiuserrors.ErrInvalidLength
	}
	val := make([]byte, attrLen-2)
	copy(val, data[2:attrLen])
	return Attribute{Type: attrType, Value: val}, data[attrLen:], nil
}

// String returns the Value interpreted as a UTF-8 string. RADIUS string
// attributes are raw octets; callers that need validation should inspect
// the result. Returns no error for any non-empty Value.
func (a Attribute) String() (string, error) {
	return string(a.Value), nil
}

// Integer returns the Value as a 4-byte big-endian unsigned integer. Returns
// ErrInvalidAttribute if Value is not exactly 4 bytes.
func (a Attribute) Integer() (uint32, error) {
	if len(a.Value) != 4 {
		return 0, radiuserrors.ErrInvalidAttribute
	}
	return binary.BigEndian.Uint32(a.Value), nil
}

// IPAddr returns the Value as a 4-byte IPv4 address. Returns ErrInvalidAttribute
// if Value is not exactly 4 bytes.
func (a Attribute) IPAddr() (net.IP, error) {
	if len(a.Value) != 4 {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	ip := make(net.IP, 4)
	copy(ip, a.Value)
	return ip, nil
}

// IPv6Addr returns the Value as a 16-byte IPv6 address. Returns
// ErrInvalidAttribute if Value is not exactly 16 bytes.
func (a Attribute) IPv6Addr() (net.IP, error) {
	if len(a.Value) != 16 {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	ip := make(net.IP, 16)
	copy(ip, a.Value)
	return ip, nil
}

// VendorSpecific deconstructs a Vendor-Specific attribute (Type 26) into the
// 4-byte Vendor-Id (big-endian; high octet conventionally 0) and the vendor-
// defined payload. Returns ErrInvalidAttribute if Value is shorter than 5
// octets (the minimum: 4-byte Vendor-Id + at least 1 byte of payload).
func (a Attribute) VendorSpecific() (vendorID uint32, data []byte, err error) {
	if len(a.Value) < 5 {
		return 0, nil, radiuserrors.ErrInvalidAttribute
	}
	vendorID = binary.BigEndian.Uint32(a.Value[:4])
	data = a.Value[4:]
	return vendorID, data, nil
}

// NewString constructs an attribute whose Value is the bytes of s.
func NewString(t byte, s string) Attribute {
	return Attribute{Type: t, Value: []byte(s)}
}

// NewInteger constructs a 4-byte big-endian integer attribute.
func NewInteger(t byte, n uint32) Attribute {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return Attribute{Type: t, Value: b}
}

// NewIPAddr constructs a 4-byte IPv4 attribute. If ip is not an IPv4 address,
// 4 zero bytes are stored; callers should validate ip before calling.
func NewIPAddr(t byte, ip net.IP) Attribute {
	v4 := ip.To4()
	if v4 == nil {
		v4 = make([]byte, 4)
	}
	return Attribute{Type: t, Value: append([]byte(nil), v4...)}
}

// NewIPv6Addr constructs a 16-byte IPv6 attribute. If ip is not 16 bytes, 16
// zero bytes are stored; callers should validate ip before calling.
func NewIPv6Addr(t byte, ip net.IP) Attribute {
	v6 := ip.To16()
	if v6 == nil {
		v6 = make([]byte, 16)
	}
	return Attribute{Type: t, Value: append([]byte(nil), v6...)}
}

// NewOctets constructs an attribute with raw octet Value. The Value slice is
// copied so callers may safely mutate b afterwards.
func NewOctets(t byte, b []byte) Attribute {
	return Attribute{Type: t, Value: append([]byte(nil), b...)}
}

// NewVendorSpecific constructs a Type 26 Vendor-Specific attribute from a
// Vendor-Id and a vendor-defined payload. The payload is copied.
func NewVendorSpecific(vendorID uint32, data []byte) Attribute {
	v := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(v, vendorID)
	copy(v[4:], data)
	return Attribute{Type: types.AttrVendorSpecific, Value: v}
}
