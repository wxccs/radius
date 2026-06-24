package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/types"
)

func TestResolveAttrType_CanonicalName(t *testing.T) {
	tp, name, err := resolveAttrType("User-Name")
	require.NoError(t, err)
	assert.Equal(t, byte(types.AttrUserName), tp)
	assert.Equal(t, "User-Name", name)
}

func TestResolveAttrType_CaseInsensitive(t *testing.T) {
	cases := []string{"user-name", "USER-NAME", "User-Name", "uSeR-nAmE"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			tp, name, err := resolveAttrType(c)
			require.NoError(t, err)
			assert.Equal(t, byte(types.AttrUserName), tp)
			assert.Equal(t, "User-Name", name)
		})
	}
}

func TestResolveAttrType_NumericInDict(t *testing.T) {
	// Numeric 4 is NAS-IP-Address in the dictionary; the canonical name is
	// returned so the caller can route through NewByName for typed encoding.
	tp, name, err := resolveAttrType("4")
	require.NoError(t, err)
	assert.Equal(t, byte(types.AttrNASIPAddress), tp)
	assert.Equal(t, "NAS-IP-Address", name)
}

func TestResolveAttrType_NumericNotInDict(t *testing.T) {
	tp, name, err := resolveAttrType("200")
	require.NoError(t, err)
	assert.Equal(t, byte(200), tp)
	assert.Empty(t, name, "unknown numeric types have no canonical name")
}

func TestResolveAttrType_OutOfRange(t *testing.T) {
	_, _, err := resolveAttrType("0")
	require.Error(t, err)
	_, _, err = resolveAttrType("256")
	require.Error(t, err)
}

func TestResolveAttrType_UnknownName(t *testing.T) {
	_, _, err := resolveAttrType("Not-An-Attribute")
	require.Error(t, err)
}

func TestAttrsFromFlags_NameValue(t *testing.T) {
	cmd := buildAttrCmd(t,
		"User-Name:alice",
		"NAS-Port:254",
		"NAS-IP-Address:192.168.1.1",
		"user-password:hunter2",
	)
	attrs, err := attrsFromFlags(cmd)
	require.NoError(t, err)
	require.Len(t, attrs, 4)

	assert.Equal(t, byte(types.AttrUserName), attrs[0].Type)
	assert.Equal(t, "alice", string(attrs[0].Value))

	assert.Equal(t, byte(types.AttrNASPort), attrs[1].Type)
	n, err := attrs[1].Integer()
	require.NoError(t, err)
	assert.Equal(t, uint32(254), n)

	assert.Equal(t, byte(types.AttrNASIPAddress), attrs[2].Type)
	assert.Len(t, attrs[2].Value, 4)
	assert.Equal(t, []byte{192, 168, 1, 1}, attrs[2].Value)

	// Case-insensitive name resolved through canonicalAttrName.
	assert.Equal(t, byte(types.AttrUserPassword), attrs[3].Type)
	assert.Equal(t, "hunter2", string(attrs[3].Value))
}

func TestAttrsFromFlags_NumericUnknownType(t *testing.T) {
	cmd := buildAttrCmd(t, "199:raw-bytes")
	attrs, err := attrsFromFlags(cmd)
	require.NoError(t, err)
	require.Len(t, attrs, 1)
	assert.Equal(t, byte(199), attrs[0].Type)
	assert.Equal(t, "raw-bytes", string(attrs[0].Value))
}

func TestAttrsFromFlags_InvalidInteger(t *testing.T) {
	cmd := buildAttrCmd(t, "NAS-Port:not-a-number")
	_, err := attrsFromFlags(cmd)
	require.Error(t, err)
}

func TestAttrsFromFlags_InvalidFormat(t *testing.T) {
	cmd := buildAttrCmd(t, "no-colon-here")
	_, err := attrsFromFlags(cmd)
	require.Error(t, err)
}

func TestAttrsFromFlags_Empty(t *testing.T) {
	cmd := buildAttrCmd(t)
	attrs, err := attrsFromFlags(cmd)
	require.NoError(t, err)
	assert.Empty(t, attrs)
}

// buildAttrCmd returns a cobra.Command with --attr flags set to the given
// values. attrsFromFlags reads from cmd.Flags().
func buildAttrCmd(t *testing.T, attrs ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().StringArray("attr", nil, "attribute as type:value (repeatable)")
	for _, a := range attrs {
		require.NoError(t, cmd.Flags().Set("attr", a))
	}
	return cmd
}
