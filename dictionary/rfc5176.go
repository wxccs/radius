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

	"github.com/wxccs/radius/v2/types"
)

// registerRFC5176 registers the single attribute defined by RFC 5176
// (Dynamic Authorization). Error-Cause (101) is a 4-byte integer whose value
// is a bit-or of the error-cause codes defined in RFC 5176 §3.4; it appears
// only in CoA-NAK and Disconnect-NAK replies.
func registerRFC5176() {
	defs := []AttributeDef{
		{Type: types.AttrErrorCause, Name: "Error-Cause", ValueType: TypeInteger},
	}
	for _, def := range defs {
		if err := defaultDict.Register(def); err != nil {
			panic(errors.New("dictionary: failed to register RFC 5176 attribute " + def.Name))
		}
	}
}
