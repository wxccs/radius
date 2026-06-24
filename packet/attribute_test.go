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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/errors"
)

func TestAttributeMarshalBinary(t *testing.T) {
	cases := []struct {
		name string
		attr Attribute
		want []byte
	}{
		{"empty_value", Attribute{Type: 24, Value: nil}, []byte{24, 2}},
		{"one_byte", Attribute{Type: 1, Value: []byte{0x41}}, []byte{1, 3, 0x41}},
		{"max_value", Attribute{Type: 26, Value: make([]byte, 253)}, append([]byte{26, 255}, make([]byte, 253)...)},
		{"string", NewString(1, "nemo"), []byte{1, 6, 'n', 'e', 'm', 'o'}},
		{"integer", NewInteger(27, 3600), []byte{27, 6, 0x00, 0x00, 0x0e, 0x10}},
		{"ipaddr", NewIPAddr(4, net.IPv4(192, 168, 1, 16)), []byte{4, 6, 192, 168, 1, 16}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.attr.MarshalBinary()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAttributeMarshalBinary_TooLong(t *testing.T) {
	a := Attribute{Type: 1, Value: make([]byte, 254)}
	_, err := a.MarshalBinary()
	assert.ErrorIs(t, err, radiuserrors.ErrAttributeTooLong)
}

func TestUnmarshalAttribute(t *testing.T) {
	cases := []struct {
		name   string
		input  []byte
		want   Attribute
		remain []byte
	}{
		{
			name:   "single_min",
			input:  []byte{24, 2},
			want:   Attribute{Type: 24, Value: []byte{}},
			remain: []byte{},
		},
		{
			name:   "with_remainder",
			input:  []byte{1, 4, 'a', 'b', 2, 2},
			want:   Attribute{Type: 1, Value: []byte{'a', 'b'}},
			remain: []byte{2, 2},
		},
		{
			name:   "max_length",
			input:  append([]byte{26, 255}, make([]byte, 253)...),
			want:   Attribute{Type: 26, Value: make([]byte, 253)},
			remain: []byte{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, remain, err := UnmarshalAttribute(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.remain, remain)
		})
	}
}

func TestUnmarshalAttribute_Errors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		_, _, err := UnmarshalAttribute(nil)
		assert.ErrorIs(t, err, radiuserrors.ErrShortBuffer)
	})
	t.Run("single_byte", func(t *testing.T) {
		_, _, err := UnmarshalAttribute([]byte{1})
		assert.ErrorIs(t, err, radiuserrors.ErrShortBuffer)
	})
	t.Run("length_below_two", func(t *testing.T) {
		_, _, err := UnmarshalAttribute([]byte{1, 1, 0})
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
	t.Run("length_zero", func(t *testing.T) {
		_, _, err := UnmarshalAttribute([]byte{1, 0})
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
	t.Run("truncated_value", func(t *testing.T) {
		_, _, err := UnmarshalAttribute([]byte{1, 6, 'a', 'b'})
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidLength)
	})
}

func TestUnmarshalAttribute_ValueIsCopy(t *testing.T) {
	input := []byte{1, 4, 'a', 'b'}
	got, _, err := UnmarshalAttribute(input)
	require.NoError(t, err)
	input[2] = 'z'
	assert.Equal(t, []byte{'a', 'b'}, got.Value, "decoded Value must be independent of input buffer")
}

func TestAttributeString(t *testing.T) {
	a := NewString(1, "nemo")
	s, err := a.String()
	require.NoError(t, err)
	assert.Equal(t, "nemo", s)
}

func TestAttributeInteger(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		a := NewInteger(5, 3)
		n, err := a.Integer()
		require.NoError(t, err)
		assert.Equal(t, uint32(3), n)
	})
	t.Run("wrong_length_3", func(t *testing.T) {
		a := Attribute{Type: 5, Value: []byte{0, 0, 0}}
		_, err := a.Integer()
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
	t.Run("wrong_length_5", func(t *testing.T) {
		a := Attribute{Type: 5, Value: make([]byte, 5)}
		_, err := a.Integer()
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
}

func TestAttributeIPAddr(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		a := NewIPAddr(4, net.IPv4(192, 168, 1, 16))
		ip, err := a.IPAddr()
		require.NoError(t, err)
		assert.True(t, ip.Equal(net.IPv4(192, 168, 1, 16)))
	})
	t.Run("wrong_length", func(t *testing.T) {
		a := Attribute{Type: 4, Value: []byte{1, 2, 3}}
		_, err := a.IPAddr()
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
}

func TestAttributeIPv6Addr(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1")
	require.NotNil(t, ipv6)
	t.Run("valid", func(t *testing.T) {
		a := NewIPv6Addr(95, ipv6)
		got, err := a.IPv6Addr()
		require.NoError(t, err)
		assert.True(t, got.Equal(ipv6))
	})
	t.Run("wrong_length", func(t *testing.T) {
		a := Attribute{Type: 95, Value: make([]byte, 15)}
		_, err := a.IPv6Addr()
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
}

func TestAttributeVendorSpecific(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		payload := []byte{0x01, 0x05, 'h', 'e', 'l'} // vendor sub-attribute
		a := NewVendorSpecific(9, payload)           // Cisco
		vendorID, data, err := a.VendorSpecific()
		require.NoError(t, err)
		assert.Equal(t, uint32(9), vendorID)
		assert.Equal(t, payload, data)
	})
	t.Run("too_short_4_bytes", func(t *testing.T) {
		a := Attribute{Type: 26, Value: []byte{0, 0, 0, 9}}
		_, _, err := a.VendorSpecific()
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
	t.Run("too_short_empty", func(t *testing.T) {
		a := Attribute{Type: 26, Value: nil}
		_, _, err := a.VendorSpecific()
		assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
	})
}

func TestNewString(t *testing.T) {
	a := NewString(1, "hello")
	assert.Equal(t, byte(1), a.Type)
	assert.Equal(t, []byte("hello"), a.Value)
}

func TestNewInteger(t *testing.T) {
	a := NewInteger(27, 0x01020304)
	assert.Equal(t, byte(27), a.Type)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, a.Value)
}

func TestNewIPAddr(t *testing.T) {
	a := NewIPAddr(4, net.IPv4(10, 0, 0, 1))
	assert.Equal(t, byte(4), a.Type)
	assert.Equal(t, []byte{10, 0, 0, 1}, a.Value)
}

func TestNewIPAddr_NonIPv4(t *testing.T) {
	// A 16-byte IPv6 address should be stored as 4 zero bytes (fallback).
	a := NewIPAddr(4, net.ParseIP("::1"))
	assert.Len(t, a.Value, 4)
}

func TestNewIPv6Addr(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1")
	a := NewIPv6Addr(95, ipv6)
	assert.Equal(t, byte(95), a.Type)
	assert.Len(t, a.Value, 16)
}

func TestNewOctets(t *testing.T) {
	src := []byte{1, 2, 3}
	a := NewOctets(60, src)
	src[0] = 99
	assert.Equal(t, []byte{1, 2, 3}, a.Value, "NewOctets must copy the input slice")
}

func TestNewVendorSpecific(t *testing.T) {
	payload := []byte{0xAB, 0xCD}
	a := NewVendorSpecific(311, payload)
	assert.Equal(t, byte(26), a.Type)
	// 311 = 0x0137; big-endian 4-byte Vendor-Id is 00 00 01 37, then payload.
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x37, 0xAB, 0xCD}, a.Value)
	assert.Equal(t, uint32(311), binary.BigEndian.Uint32(a.Value[:4]))
}
