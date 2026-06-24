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

package dictionary

import (
	"errors"

	"github.com/wxccs/radius/types"
)

// registerRFC6929 registers the extended attribute type codes defined by
// RFC 6929. These types (241-244) introduce a new attribute header format
// that allows more than 255 attribute types and, for type 242 ("long
// extended"), values up to 4111 octets across multiple fragments.
//
// The dictionary records them as TypeExtended so callers can dispatch to the
// extended-attribute codec. Full codec behavior (more-type flag, long-extended
// fragmentation) is implemented in the packet layer.
func registerRFC6929() {
	defs := []AttributeDef{
		{Type: types.AttrExtendedType1, Name: "Extended-Type-1", ValueType: TypeExtended},
		{Type: types.AttrExtendedType2, Name: "Extended-Type-2", ValueType: TypeExtended},
		{Type: types.AttrExtendedType3, Name: "Extended-Type-3", ValueType: TypeExtended},
		{Type: types.AttrExtendedType4, Name: "Extended-Type-4", ValueType: TypeExtended},
	}
	for _, def := range defs {
		if err := defaultDict.Register(def); err != nil {
			panic(errors.New("dictionary: failed to register RFC 6929 attribute " + def.Name))
		}
	}
}
