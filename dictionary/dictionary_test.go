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

package dictionary

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/errors"
)

func TestValueTypeString(t *testing.T) {
	cases := []struct {
		v    ValueType
		want string
	}{
		{TypeString, "string"},
		{TypeInteger, "integer"},
		{TypeIPAddr, "ipaddr"},
		{TypeIPv6Addr, "ipv6addr"},
		{TypeOctets, "octets"},
		{TypeVSA, "vsa"},
		{TypeExtended, "extended"},
		{ValueType(99), "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.v.String())
		})
	}
}

func TestDefaultDictionaryHasStandardAttributes(t *testing.T) {
	// init() registers the RFC 2865 and RFC 2866 standard attributes.
	cases := []struct {
		typeVal   byte
		name      string
		valueType ValueType
	}{
		{1, "User-Name", TypeString},
		{2, "User-Password", TypeString},
		{4, "NAS-IP-Address", TypeIPAddr},
		{5, "NAS-Port", TypeInteger},
		{26, "Vendor-Specific", TypeVSA},
		{27, "Session-Timeout", TypeInteger},
		{40, "Acct-Status-Type", TypeInteger},
		{44, "Acct-Session-Id", TypeString},
		{50, "Acct-Multi-Session-Id", TypeString},
		{63, "Login-LAT-Port", TypeString},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, ok := Default().Lookup(tc.typeVal)
			require.True(t, ok, "attribute %d must be registered", tc.typeVal)
			assert.Equal(t, tc.name, def.Name)
			assert.Equal(t, tc.valueType, def.ValueType)

			byName, ok := Default().LookupName(tc.name)
			require.True(t, ok)
			assert.Equal(t, tc.typeVal, byName.Type)
		})
	}
}

func TestDefaultDictionary_UserPasswordMarkedEncrypted(t *testing.T) {
	def, ok := Default().Lookup(2)
	require.True(t, ok)
	assert.Equal(t, 1, def.Encrypt, "User-Password must be flagged as encrypted")
}

func TestDefaultDictionary_Size(t *testing.T) {
	// RFC 2865 §5 defines 41 attribute types (1-16, 18-20, 22-39, 60-63;
	// Types 17 and 21 are not assigned).
	// RFC 2866 §5 defines 12 accounting attribute types (40-51).
	// Total: 53.
	assert.Equal(t, 53, Default().Size())
}

func TestDictionary_RegisterAndLookup(t *testing.T) {
	d := New()
	def := AttributeDef{Type: 99, Name: "Site-Local-Attr", ValueType: TypeOctets}
	require.NoError(t, d.Register(def))

	got, ok := d.Lookup(99)
	require.True(t, ok)
	assert.Equal(t, "Site-Local-Attr", got.Name)

	byName, ok := d.LookupName("Site-Local-Attr")
	require.True(t, ok)
	assert.Equal(t, byte(99), byName.Type)
}

func TestDictionary_RegisterEmptyNameFails(t *testing.T) {
	d := New()
	err := d.Register(AttributeDef{Type: 7, Name: "", ValueType: TypeString})
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}

func TestDictionary_ReregisterSameType(t *testing.T) {
	d := New()
	require.NoError(t, d.Register(AttributeDef{Type: 99, Name: "First", ValueType: TypeString}))
	require.NoError(t, d.Register(AttributeDef{Type: 99, Name: "Second", ValueType: TypeInteger}))

	// Old name must no longer resolve.
	_, ok := d.LookupName("First")
	assert.False(t, ok, "stale name binding must be removed on re-registration")

	got, ok := d.Lookup(99)
	require.True(t, ok)
	assert.Equal(t, "Second", got.Name)
}

func TestDictionary_LookupMissing(t *testing.T) {
	d := New()
	_, ok := d.Lookup(42)
	assert.False(t, ok)
	_, ok = d.LookupName("no-such-attr")
	assert.False(t, ok)
}

func TestResetForTest(t *testing.T) {
	// Snapshot the default dictionary and restore it after the test so that
	// other tests in this package continue to see the RFC 2865/2866 entries.
	t.Cleanup(func() {
		ResetForTest()
		registerRFC2865()
		registerRFC2866()
	})

	ResetForTest()
	assert.Equal(t, 0, Default().Size(), "ResetForTest must clear the default dictionary")

	_, ok := Default().Lookup(1)
	assert.False(t, ok, "User-Name must be gone after ResetForTest")
}

func TestRegisterIntoDefault(t *testing.T) {
	// Snapshot/restore to keep the global dictionary clean.
	t.Cleanup(func() {
		ResetForTest()
		registerRFC2865()
		registerRFC2866()
	})

	require.NoError(t, Register(AttributeDef{Type: 200, Name: "Test-Attr", ValueType: TypeOctets}))
	def, ok := Default().Lookup(200)
	require.True(t, ok)
	assert.Equal(t, "Test-Attr", def.Name)
}

func TestDictionary_ConcurrentAccess(t *testing.T) {
	// Run the race detector over concurrent Register/Lookup against the same
	// Dictionary instance.
	d := New()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = d.Register(AttributeDef{
				Type:      byte(i),
				Name:      "Attr-" + string(rune('A'+i%26)),
				ValueType: TypeString,
			})
			_, _ = d.Lookup(byte(i % 25))
		}(i)
	}
	wg.Wait()
}

func TestDefaultDictionaryNotNil(t *testing.T) {
	// Calling Default() multiple times returns the same instance.
	d1 := Default()
	d2 := Default()
	assert.Same(t, d1, d2)
}

func TestRegister_EmptyNameReturnsSentinel(t *testing.T) {
	// Direct callers of Register receive a wrapped sentinel error.
	err := New().Register(AttributeDef{Type: 1, Name: ""})
	require.Error(t, err)
	assert.ErrorIs(t, err, radiuserrors.ErrInvalidAttribute)
}
