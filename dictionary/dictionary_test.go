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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/v2/errors"
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
	// RFC 2865 §5: 41 attribute types (1-16, 18-20, 22-39, 60-63).
	// RFC 2866 §5: 12 accounting attribute types (40-51).
	// RFC 2868: 10 tunnel attribute types (64-67, 69, 81-83, 90, 91).
	// RFC 2869: 14 extension attribute types (70-80, 85, 87, 88).
	// RFC 3162: 6 IPv6 attribute types (95-100).
	// RFC 5176: 1 attribute type (101 Error-Cause).
	// RFC 6929: 4 extended attribute types (241-244).
	// Total: 41 + 12 + 10 + 14 + 6 + 1 + 4 = 88.
	assert.Equal(t, 88, Default().Size())
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
	// other tests in this package continue to see the full RFC attribute set.
	t.Cleanup(func() {
		ResetForTest()
		registerStandardAttributes()
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
		registerStandardAttributes()
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

func TestDefaultDictionary_RFC2868TunnelAttributes(t *testing.T) {
	cases := []struct {
		typeVal byte
		name    string
		encrypt int
		hasTag  bool
	}{
		{64, "Tunnel-Type", 0, true},
		{65, "Tunnel-Medium-Type", 0, true},
		{66, "Tunnel-Client-Endpoint", 0, true},
		{67, "Tunnel-Server-Endpoint", 0, true},
		{69, "Tunnel-Password", 1, true},
		{81, "Tunnel-Private-Group-Id", 0, true},
		{82, "Tunnel-Assignment-Id", 0, true},
		{83, "Tunnel-Preference", 0, true},
		{90, "Tunnel-Client-Auth-Id", 0, true},
		{91, "Tunnel-Server-Auth-Id", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, ok := Default().Lookup(tc.typeVal)
			require.True(t, ok, "RFC 2868 attribute %d must be registered", tc.typeVal)
			assert.Equal(t, tc.name, def.Name)
			assert.Equal(t, tc.hasTag, def.HasTag, "%s must have HasTag=true", tc.name)
			assert.Equal(t, tc.encrypt, def.Encrypt, "%s Encrypt mismatch", tc.name)
		})
	}
}

func TestDefaultDictionary_RFC2869Extensions(t *testing.T) {
	cases := []struct {
		typeVal   byte
		name      string
		valueType ValueType
	}{
		{70, "ARAP-Password", TypeOctets},
		{71, "ARAP-Features", TypeOctets},
		{72, "ARAP-Zone-Access", TypeInteger},
		{73, "ARAP-Security", TypeInteger},
		{74, "ARAP-Security-Data", TypeOctets},
		{75, "Password-Retry", TypeInteger},
		{76, "Prompt", TypeInteger},
		{77, "Connect-Info", TypeString},
		{78, "Configuration-Token", TypeString},
		{79, "EAP-Message", TypeOctets},
		{80, "Message-Authenticator", TypeOctets},
		{85, "Acct-Interim-Interval", TypeInteger},
		{87, "NAS-Port-Id", TypeString},
		{88, "Framed-Pool", TypeString},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, ok := Default().Lookup(tc.typeVal)
			require.True(t, ok, "RFC 2869 attribute %d must be registered", tc.typeVal)
			assert.Equal(t, tc.name, def.Name)
			assert.Equal(t, tc.valueType, def.ValueType)
		})
	}
}

func TestDefaultDictionary_RFC3162IPv6Attributes(t *testing.T) {
	cases := []struct {
		typeVal   byte
		name      string
		valueType ValueType
	}{
		{95, "NAS-IPv6-Address", TypeIPv6Addr},
		{96, "Framed-Interface-Id", TypeOctets},
		{97, "Framed-IPv6-Prefix", TypeOctets},
		{98, "Login-IPv6-Host", TypeIPv6Addr},
		{99, "Framed-IPv6-Route", TypeString},
		{100, "Framed-IPv6-Pool", TypeString},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, ok := Default().Lookup(tc.typeVal)
			require.True(t, ok, "RFC 3162 attribute %d must be registered", tc.typeVal)
			assert.Equal(t, tc.name, def.Name)
			assert.Equal(t, tc.valueType, def.ValueType)
		})
	}
}

func TestDefaultDictionary_RFC5176ErrorCause(t *testing.T) {
	def, ok := Default().Lookup(101)
	require.True(t, ok, "Error-Cause must be registered")
	assert.Equal(t, "Error-Cause", def.Name)
	assert.Equal(t, TypeInteger, def.ValueType)

	byName, ok := Default().LookupName("Error-Cause")
	require.True(t, ok)
	assert.Equal(t, byte(101), byName.Type)
}

func TestDefaultDictionary_RFC6929ExtendedTypes(t *testing.T) {
	cases := []struct {
		typeVal byte
		name    string
	}{
		{241, "Extended-Type-1"},
		{242, "Extended-Type-2"},
		{243, "Extended-Type-3"},
		{244, "Extended-Type-4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, ok := Default().Lookup(tc.typeVal)
			require.True(t, ok, "RFC 6929 attribute %d must be registered", tc.typeVal)
			assert.Equal(t, tc.name, def.Name)
			assert.Equal(t, TypeExtended, def.ValueType)
		})
	}
}
