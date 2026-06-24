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
	radiuserrors "github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

// RFC 6929 extended-attribute wire format:
//
//   Extended (types 241, 243, 244):
//     +------+--------+---------------+---------------------------+
//     | Type | Length | Extended-Type | Value ...                 |
//     +------+--------+---------------+---------------------------+
//     1 byte  1 byte    1 byte          Length-3 bytes (0..253)
//
//   Long Extended (type 242):
//     +------+--------+---------------+------+---------------------+
//     | Type | Length | Extended-Type | More | Value ...           |
//     +------+--------+---------------+------+---------------------+
//     1 byte  1 byte    1 byte          1 bit  Length-4 bytes (0..251)
//
// The More bit (0x80 of the 4th octet) signals that the value continues in
// the next attribute of the same Type+Extended-Type. Fragments are
// reassembled in order; the total reassembled value may be up to 4111
// octets (RFC 6929 §2.2).
//
// The low 7 bits of the 4th octet are reserved and MUST be ignored on
// receive and sent as zero on transmit.

// extendedTypeIsLong reports whether the given outer Type uses the long
// extended format (carrying a More flag). Only Type 242 is long extended
// per RFC 6929 §2.2.
func extendedTypeIsLong(t byte) bool {
	return t == types.AttrExtendedType2
}

// isExtendedType reports whether t is one of the four RFC 6929 extended
// attribute type codes (241-244).
func isExtendedType(t byte) bool {
	switch t {
	case types.AttrExtendedType1, types.AttrExtendedType2,
		types.AttrExtendedType3, types.AttrExtendedType4:
		return true
	}
	return false
}

// ExtendedAttribute is a decoded RFC 6929 extended attribute. It exposes the
// inner Extended-Type and the reassembled Value (across all fragments for
// long extended attributes). More is preserved on marshal for callers that
// want to emit a single fragment with the More bit set; for typical use the
// helper MarshalExtendedFragments splits an over-long value automatically.
type ExtendedAttribute struct {
	// Type is the outer attribute type (241..244).
	Type byte
	// ExtendedType is the inner per-RFC-6929 attribute type.
	ExtendedType byte
	// Value is the reassembled value, with the More/Flags header removed.
	Value []byte
}

// MarshalExtended encodes a single extended attribute into wire format.
// For long extended (Type 242) the More bit is set to 0 (terminal fragment).
// Use MarshalExtendedFragments when the value may exceed one attribute.
//
// Returns ErrAttributeTooLong if Value exceeds the per-attribute maximum
// (253 for types 241/243/244, 251 for type 242).
func (e ExtendedAttribute) MarshalExtended() ([]byte, error) {
	if !isExtendedType(e.Type) {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	maxVal := types.AttrValueMaxLength // 253
	if extendedTypeIsLong(e.Type) {
		maxVal = 251
	}
	if len(e.Value) > maxVal {
		return nil, radiuserrors.ErrAttributeTooLong
	}

	headerLen := 3
	if extendedTypeIsLong(e.Type) {
		headerLen = 4
	}
	out := make([]byte, headerLen+len(e.Value))
	out[0] = e.Type
	out[1] = byte(headerLen + len(e.Value))
	out[2] = e.ExtendedType
	if extendedTypeIsLong(e.Type) {
		out[3] = 0 // More=0, flags=0
	}
	copy(out[headerLen:], e.Value)
	return out, nil
}

// UnmarshalExtended decodes a single extended attribute from the start of
// data and returns it alongside the remaining bytes. For long extended
// attributes the More bit is recorded on the returned ExtendedAttribute's
// More field via a separate accessor; this function decodes exactly one
// fragment and does not reassemble. Callers that need reassembly should
// use UnmarshalExtendedReassembled over a sequence of fragments.
//
// The returned Value is a copy.
func UnmarshalExtended(data []byte) (ExtendedAttribute, []byte, error) {
	if len(data) < 2 {
		return ExtendedAttribute{}, nil, radiuserrors.ErrShortBuffer
	}
	t := data[0]
	if !isExtendedType(t) {
		return ExtendedAttribute{}, nil, radiuserrors.ErrInvalidAttribute
	}
	length := int(data[1])
	if length < 3 {
		return ExtendedAttribute{}, nil, radiuserrors.ErrInvalidAttribute
	}
	if extendedTypeIsLong(t) && length < 4 {
		return ExtendedAttribute{}, nil, radiuserrors.ErrInvalidAttribute
	}
	if length > len(data) {
		return ExtendedAttribute{}, nil, radiuserrors.ErrInvalidLength
	}

	headerLen := 3
	if extendedTypeIsLong(t) {
		headerLen = 4
	}
	ext := ExtendedAttribute{
		Type:         t,
		ExtendedType: data[2],
	}
	val := make([]byte, length-headerLen)
	copy(val, data[headerLen:length])
	ext.Value = val
	return ext, data[length:], nil
}

// ExtendedMore reports whether the fragment carries the More bit set. Only
// meaningful for long extended (Type 242) attributes; non-long types always
// return false.
func ExtendedMore(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	if !extendedTypeIsLong(raw[0]) {
		return false
	}
	return raw[3]&0x80 != 0
}

// MarshalExtendedFragments encodes an extended attribute, splitting the
// value across multiple long-extended (Type 242) fragments when it exceeds
// the per-attribute maximum. Non-long types (241/243/244) emit a single
// fragment and return ErrAttributeTooLong if the value is too long.
//
// The returned slice is the concatenation of all fragment wire encodings,
// ready to be appended into a packet's attribute section.
func MarshalExtendedFragments(e ExtendedAttribute) ([]byte, error) {
	if !isExtendedType(e.Type) {
		return nil, radiuserrors.ErrInvalidAttribute
	}
	if !extendedTypeIsLong(e.Type) {
		return e.MarshalExtended()
	}

	// Long extended: 251 bytes per fragment, More bit set on all but the last.
	const fragMax = 251
	if len(e.Value) == 0 {
		// Emit a single empty fragment with More=0.
		return e.MarshalExtended()
	}

	var out []byte
	off := 0
	for off < len(e.Value) {
		end := min(off+fragMax, len(e.Value))
		chunk := e.Value[off:end]
		off = end

		more := byte(0)
		if off < len(e.Value) {
			more = 0x80
		}
		frag := make([]byte, 4+len(chunk))
		frag[0] = e.Type
		frag[1] = byte(4 + len(chunk))
		frag[2] = e.ExtendedType
		frag[3] = more
		copy(frag[4:], chunk)
		out = append(out, frag...)
	}
	return out, nil
}

// UnmarshalExtendedReassembled scans a slice of attribute bytes, decodes
// consecutive extended fragments with the same Type+Extended-Type, and
// returns the reassembled ExtendedAttribute plus the remaining unconsumed
// bytes. The More bit chains fragments together per RFC 6929 §2.2.
//
// For non-long extended types, returns the single attribute immediately.
func UnmarshalExtendedReassembled(data []byte) (ExtendedAttribute, []byte, error) {
	first, remain, err := UnmarshalExtended(data)
	if err != nil {
		return ExtendedAttribute{}, nil, err
	}
	if !extendedTypeIsLong(first.Type) {
		return first, remain, nil
	}

	// Reassemble long-extended fragments. The current fragment's More bit
	// is in data[3]; we check it before advancing to the next fragment.
	value := append([]byte(nil), first.Value...)
	t := first.Type
	extType := first.ExtendedType
	current := data

	for ExtendedMore(current) {
		current = remain
		if len(current) == 0 {
			// More was set but no further fragment follows — malformed.
			return ExtendedAttribute{}, nil, radiuserrors.ErrInvalidAttribute
		}
		next, nextRemain, err := UnmarshalExtended(current)
		if err != nil {
			return ExtendedAttribute{}, nil, err
		}
		if next.Type != t || next.ExtendedType != extType {
			return ExtendedAttribute{}, nil, radiuserrors.ErrInvalidAttribute
		}
		value = append(value, next.Value...)
		remain = nextRemain
	}

	first.Value = value
	return first, remain, nil
}
