package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wxccs/radius/v2/dictionary/parser"
)

func TestRegisterFromDict_BasicAttributes(t *testing.T) {
	p := &parser.Dict{Attributes: []parser.Attr{
		{Name: "User-Name", Type: 1, ValueType: "string"},
		{Name: "NAS-Port", Type: 5, ValueType: "integer"},
		{Name: "NAS-IP-Address", Type: 4, ValueType: "ipaddr"},
	}}
	d := New()
	require.NoError(t, d.RegisterFromDict(p))

	def, ok := d.LookupName("User-Name")
	require.True(t, ok)
	assert.Equal(t, TypeString, def.ValueType)
	assert.Equal(t, byte(1), def.Type)

	def, ok = d.LookupName("NAS-Port")
	require.True(t, ok)
	assert.Equal(t, TypeInteger, def.ValueType)

	// Reverse lookup by Type
	def, ok = d.Lookup(4)
	require.True(t, ok)
	assert.Equal(t, "NAS-IP-Address", def.Name)
}

func TestRegisterFromDict_RawTypePreserved(t *testing.T) {
	// After parser.Parse normalizes unknown FreeRADIUS type tokens to
	// "raw", RegisterFromDict maps that to TypeRaw so callers can still
	// round-trip the attribute as opaque octets.
	p := &parser.Dict{Attributes: []parser.Attr{
		{Name: "TLS-Session-Info", Type: 145, ValueType: "raw"},
		{Name: "CU-Identity", Type: 89, ValueType: "raw"},
	}}
	d := New()
	require.NoError(t, d.RegisterFromDict(p))

	for _, n := range []string{"TLS-Session-Info", "CU-Identity"} {
		def, ok := d.LookupName(n)
		require.True(t, ok)
		assert.Equal(t, TypeRaw, def.ValueType, "%s must map to TypeRaw", n)
		assert.Equal(t, "raw", def.ValueType.String())
	}
}

func TestRegisterFromDict_FlagsPropagated(t *testing.T) {
	p := &parser.Dict{Attributes: []parser.Attr{
		{Name: "User-Password", Type: 2, ValueType: "string", Encrypt: 1},
		{Name: "Tunnel-Type", Type: 64, ValueType: "integer", HasTag: true},
	}}
	d := New()
	require.NoError(t, d.RegisterFromDict(p))

	def, _ := d.LookupName("User-Password")
	assert.Equal(t, 1, def.Encrypt)
	assert.False(t, def.HasTag)

	def, _ = d.LookupName("Tunnel-Type")
	assert.True(t, def.HasTag)
}

func TestRegisterFromDict_NilSafe(t *testing.T) {
	d := New()
	assert.NoError(t, d.RegisterFromDict(nil))
}

func TestRegisterFromDict_UnknownTypeStringRejected(t *testing.T) {
	// If a caller hand-builds a parser.Dict with an unknown ValueType
	// string (skipping the parser's normalization), RegisterFromDict
	// surfaces an error rather than silently dropping the entry.
	p := &parser.Dict{Attributes: []parser.Attr{
		{Name: "Bogus", Type: 200, ValueType: "this-should-never-happen"},
	}}
	d := New()
	err := d.RegisterFromDict(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown value type")
}

func TestRegisterFromDict_LastWriteWins(t *testing.T) {
	// Two dicts each defining attribute 1 with a different name. When
	// merged into a single *Dict and registered, the second registration
	// must overwrite the first — matching Register() semantics.
	p := &parser.Dict{Attributes: []parser.Attr{
		{Name: "First", Type: 1, ValueType: "string"},
		{Name: "Second", Type: 1, ValueType: "integer"},
	}}
	d := New()
	require.NoError(t, d.RegisterFromDict(p))

	def, ok := d.Lookup(1)
	require.True(t, ok)
	assert.Equal(t, "Second", def.Name)
	assert.Equal(t, TypeInteger, def.ValueType)

	// The stale name binding must be gone.
	_, ok = d.LookupName("First")
	assert.False(t, ok, "first name binding must be cleared after re-register")
}
