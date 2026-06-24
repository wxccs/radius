package packet

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/dictionary"
	"github.com/wxccs/radius/types"
)

func TestFormat_NilPacket(t *testing.T) {
	assert.Equal(t, "<nil packet>", Format(nil, dictionary.Default()))
}

func TestFormat_AccessRequest(t *testing.T) {
	p := &Packet{
		Code:          types.AccessRequest,
		Identifier:    7,
		Authenticator: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Attributes: []Attribute{
			NewString(types.AttrUserName, "alice"),
			NewString(types.AttrUserPassword, "hunter2"),
			NewIPAddr(types.AttrNASIPAddress, net.IPv4(192, 168, 1, 1).To4()),
			NewInteger(types.AttrNASPort, 254),
		},
	}

	got := Format(p, dictionary.Default())
	assert.Contains(t, got, "Code: Access-Request (1)")
	assert.Contains(t, got, "ID: 7")
	assert.Contains(t, got, "User-Name (1) = \"alice\"")
	assert.Contains(t, got, "User-Password (2) = <encrypted>")
	assert.Contains(t, got, "NAS-IP-Address (4) = 192.168.1.1")
	assert.Contains(t, got, "NAS-Port (5) = 254")
}

func TestFormat_NoDictionary(t *testing.T) {
	p := &Packet{
		Code:       types.AccessRequest,
		Identifier: 1,
		Attributes: []Attribute{
			NewString(types.AttrUserName, "alice"),
		},
	}
	got := Format(p, nil)
	// Without dict the name falls back to <unknown> and value to a hex fallback.
	assert.Contains(t, got, "<unknown>")
}

func TestFormat_EmptyAttributes(t *testing.T) {
	p := &Packet{
		Code:          types.AccessReject,
		Identifier:    2,
		Authenticator: [16]byte{},
	}
	got := Format(p, dictionary.Default())
	assert.True(t, strings.HasPrefix(got, "Code: Access-Reject (3)"))
	assert.NotContains(t, got, "Attributes:")
}

func TestFormatAttribute_VSA(t *testing.T) {
	a := NewVendorSpecific(9, []byte{0x01, 0x02})
	got := FormatAttribute(a, dictionary.Default())
	assert.Contains(t, got, "Vendor-Specific (26)")
	assert.Contains(t, got, "vendor=9")
	assert.Contains(t, got, "data=0102")
}

func TestFormatAttribute_IPv6(t *testing.T) {
	a := NewIPv6Addr(types.AttrNASIPv6Address, net.ParseIP("2001:db8::1"))
	got := FormatAttribute(a, dictionary.Default())
	assert.Contains(t, got, "NAS-IPv6-Address (95)")
	assert.Contains(t, got, "2001:db8::1")
}

func TestFormatAttribute_Octets(t *testing.T) {
	a := NewOctets(types.AttrState, []byte{0xde, 0xad, 0xbe, 0xef})
	got := FormatAttribute(a, dictionary.Default())
	assert.Contains(t, got, "State (24)")
	assert.Contains(t, got, "hex:deadbeef")
}

func TestFormat_AttributeSlicesAreNotMutated(t *testing.T) {
	attrs := []Attribute{NewString(types.AttrUserName, "alice")}
	p := &Packet{
		Code:       types.AccessRequest,
		Identifier: 1,
		Attributes: attrs,
	}
	_ = Format(p, dictionary.Default())
	require.Equal(t, "alice", string(attrs[0].Value), "Format must not mutate input")
}
