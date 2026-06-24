// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 wxccs
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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

func TestExtendedAttribute_MarshalShort(t *testing.T) {
	// Type 241 (non-long): header = Type + Length + Extended-Type = 3 bytes.
	e := ExtendedAttribute{Type: types.AttrExtendedType1, ExtendedType: 7, Value: []byte("hi")}
	raw, err := e.MarshalExtended()
	require.NoError(t, err)
	want := []byte{241, 5, 7, 'h', 'i'}
	assert.Equal(t, want, raw)
}

func TestExtendedAttribute_MarshalLong(t *testing.T) {
	// Type 242 (long): header = Type + Length + Extended-Type + More/Flags = 4 bytes.
	e := ExtendedAttribute{Type: types.AttrExtendedType2, ExtendedType: 9, Value: []byte("xx")}
	raw, err := e.MarshalExtended()
	require.NoError(t, err)
	want := []byte{242, 6, 9, 0, 'x', 'x'}
	assert.Equal(t, want, raw)
}

func TestExtendedAttribute_MarshalRejectsNonExtendedType(t *testing.T) {
	_, err := ExtendedAttribute{Type: 1, ExtendedType: 1, Value: []byte("x")}.MarshalExtended()
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}

func TestExtendedAttribute_MarshalValueTooLong_ShortType(t *testing.T) {
	e := ExtendedAttribute{
		Type:         types.AttrExtendedType1,
		ExtendedType: 1,
		Value:        make([]byte, 254), // exceeds 253
	}
	_, err := e.MarshalExtended()
	assert.ErrorIs(t, err, radiuserrors.ErrAttributeTooLong)
}

func TestExtendedAttribute_MarshalValueTooLong_LongType(t *testing.T) {
	e := ExtendedAttribute{
		Type:         types.AttrExtendedType2,
		ExtendedType: 1,
		Value:        make([]byte, 252), // exceeds 251
	}
	_, err := e.MarshalExtended()
	assert.ErrorIs(t, err, radiuserrors.ErrAttributeTooLong)
}

func TestUnmarshalExtended_ShortType(t *testing.T) {
	raw := []byte{241, 5, 7, 'h', 'i', 0xFF /* trailing bytes ignored */}
	e, remain, err := UnmarshalExtended(raw)
	require.NoError(t, err)
	assert.Equal(t, byte(241), e.Type)
	assert.Equal(t, byte(7), e.ExtendedType)
	assert.Equal(t, []byte("hi"), e.Value)
	assert.Equal(t, []byte{0xFF}, remain)
}

func TestUnmarshalExtended_LongType(t *testing.T) {
	raw := []byte{242, 6, 9, 0x80, 'a', 'b'} // More bit set
	e, remain, err := UnmarshalExtended(raw)
	require.NoError(t, err)
	assert.Equal(t, byte(242), e.Type)
	assert.Equal(t, byte(9), e.ExtendedType)
	assert.Equal(t, []byte("ab"), e.Value)
	assert.Empty(t, remain)
	assert.True(t, ExtendedMore(raw), "More bit must be observed")
}

func TestUnmarshalExtended_NonExtendedType(t *testing.T) {
	_, _, err := UnmarshalExtended([]byte{1, 5, 'h', 'i', 'x'})
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}

func TestUnmarshalExtended_ShortBuffer(t *testing.T) {
	_, _, err := UnmarshalExtended([]byte{241})
	assert.ErrorIs(t, err, radiuserrors.ErrShortBuffer)
}

func TestUnmarshalExtended_LengthExceedsData(t *testing.T) {
	raw := []byte{241, 10, 7, 'a'} // claims 10 bytes, only 4 present
	_, _, err := UnmarshalExtended(raw)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidLength)
}

func TestMarshalExtendedFragments_NonLongSingleFragment(t *testing.T) {
	e := ExtendedAttribute{Type: types.AttrExtendedType1, ExtendedType: 3, Value: []byte("payload")}
	out, err := MarshalExtendedFragments(e)
	require.NoError(t, err)
	want, _ := e.MarshalExtended()
	assert.Equal(t, want, out)
}

func TestMarshalExtendedFragments_LongSingleFragment(t *testing.T) {
	e := ExtendedAttribute{Type: types.AttrExtendedType2, ExtendedType: 3, Value: []byte("payload")}
	out, err := MarshalExtendedFragments(e)
	require.NoError(t, err)
	// Single fragment, More=0.
	want := []byte{242, 11, 3, 0, 'p', 'a', 'y', 'l', 'o', 'a', 'd'}
	assert.Equal(t, want, out)
}

func TestMarshalExtendedFragments_SplitsLongValue(t *testing.T) {
	// Value of 300 bytes must split into 251 + 49 across two fragments.
	value := bytes.Repeat([]byte{0xAB}, 300)
	e := ExtendedAttribute{Type: types.AttrExtendedType2, ExtendedType: 5, Value: value}
	out, err := MarshalExtendedFragments(e)
	require.NoError(t, err)

	// First fragment: Type=242, Length=255, ExtType=5, More=0x80, 251 bytes.
	require.GreaterOrEqual(t, len(out), 255)
	assert.Equal(t, byte(242), out[0])
	assert.Equal(t, byte(255), out[1])
	assert.Equal(t, byte(5), out[2])
	assert.Equal(t, byte(0x80), out[3], "first fragment must set More bit")
	assert.Equal(t, value[:251], out[4:255])

	// Second fragment: Type=242, Length=53, ExtType=5, More=0, 49 bytes.
	rest := out[255:]
	assert.Equal(t, byte(242), rest[0])
	assert.Equal(t, byte(53), rest[1])
	assert.Equal(t, byte(5), rest[2])
	assert.Equal(t, byte(0), rest[3], "last fragment must clear More bit")
	assert.Equal(t, value[251:], rest[4:])
}

func TestUnmarshalExtendedReassembled_NonLong(t *testing.T) {
	raw := []byte{241, 5, 7, 'h', 'i'}
	e, remain, err := UnmarshalExtendedReassembled(raw)
	require.NoError(t, err)
	assert.Equal(t, byte(241), e.Type)
	assert.Equal(t, byte(7), e.ExtendedType)
	assert.Equal(t, []byte("hi"), e.Value)
	assert.Empty(t, remain)
}

func TestUnmarshalExtendedReassembled_LongMultiFragment(t *testing.T) {
	value := bytes.Repeat([]byte{0xCD}, 300)
	e := ExtendedAttribute{Type: types.AttrExtendedType2, ExtendedType: 5, Value: value}
	wire, err := MarshalExtendedFragments(e)
	require.NoError(t, err)

	got, remain, err := UnmarshalExtendedReassembled(wire)
	require.NoError(t, err)
	assert.Equal(t, byte(242), got.Type)
	assert.Equal(t, byte(5), got.ExtendedType)
	assert.Equal(t, value, got.Value)
	assert.Empty(t, remain)
}

func TestUnmarshalExtendedReassembled_LongMultiFragmentWithTrailer(t *testing.T) {
	value := bytes.Repeat([]byte{0xCD}, 300)
	e := ExtendedAttribute{Type: types.AttrExtendedType2, ExtendedType: 5, Value: value}
	wire, err := MarshalExtendedFragments(e)
	require.NoError(t, err)

	// Append a non-extended attribute after the fragments.
	trailer := []byte{1, 5, 'h', 'i', '!'}
	full := append(wire, trailer...)

	got, remain, err := UnmarshalExtendedReassembled(full)
	require.NoError(t, err)
	assert.Equal(t, value, got.Value)
	assert.Equal(t, trailer, remain)
}

func TestUnmarshalExtendedReassembled_MoreBitWithoutFollowingFragment(t *testing.T) {
	// Claims More but no subsequent fragment — malformed.
	raw := []byte{242, 5, 9, 0x80, 'a'}
	_, _, err := UnmarshalExtendedReassembled(raw)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}

func TestExtendedMore_NonLongTypeAlwaysFalse(t *testing.T) {
	raw := []byte{241, 5, 7, 0x80, 'a'}
	assert.False(t, ExtendedMore(raw))
}

func TestExtendedMore_ShortBuffer(t *testing.T) {
	assert.False(t, ExtendedMore([]byte{242, 2}))
}

func TestRoundTrip_AllExtendedTypes(t *testing.T) {
	cases := []struct {
		name   string
		extTyp byte
	}{
		{"type241", types.AttrExtendedType1},
		{"type242", types.AttrExtendedType2},
		{"type243", types.AttrExtendedType3},
		{"type244", types.AttrExtendedType4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := ExtendedAttribute{Type: tc.extTyp, ExtendedType: 42, Value: []byte("round-trip")}
			wire, err := MarshalExtendedFragments(e)
			require.NoError(t, err)
			got, remain, err := UnmarshalExtendedReassembled(wire)
			require.NoError(t, err)
			assert.Empty(t, remain)
			assert.Equal(t, tc.extTyp, got.Type)
			assert.Equal(t, byte(42), got.ExtendedType)
			assert.Equal(t, []byte("round-trip"), got.Value)
		})
	}
}
