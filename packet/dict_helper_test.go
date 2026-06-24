package packet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/radius/dictionary"
	"github.com/wxccs/radius/errors"
	"github.com/wxccs/radius/types"
)

func TestNewByName_StringAndOctets(t *testing.T) {
	d := dictionary.Default()

	a, err := NewByName(d, "User-Name", "alice")
	require.NoError(t, err)
	assert.Equal(t, byte(types.AttrUserName), a.Type)
	assert.Equal(t, "alice", string(a.Value))

	// State is TypeOctets in the dictionary; both string and []byte accepted.
	a2, err := NewByName(d, "State", "opaque-state")
	require.NoError(t, err)
	assert.Equal(t, []byte("opaque-state"), a2.Value)

	a3, err := NewByName(d, "State", []byte{0xde, 0xad})
	require.NoError(t, err)
	assert.Equal(t, []byte{0xde, 0xad}, a3.Value)
}

func TestNewByName_Integer(t *testing.T) {
	d := dictionary.Default()

	cases := []struct {
		name  string
		value any
		want  uint32
	}{
		{"uint32", uint32(42), 42},
		{"int", int(7), 7},
		{"uint", uint(7), 7},
		{"string", "123", 123},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := NewByName(d, "NAS-Port", c.value)
			require.NoError(t, err)
			n, err := a.Integer()
			require.NoError(t, err)
			assert.Equal(t, c.want, n)
		})
	}
}

func TestNewByName_IP(t *testing.T) {
	d := dictionary.Default()

	a, err := NewByName(d, "NAS-IP-Address", "192.168.1.1")
	require.NoError(t, err)
	assert.Equal(t, net.IPv4(192, 168, 1, 1).To4(), net.IP(a.Value))

	a2, err := NewByName(d, "NAS-IP-Address", net.IPv4(10, 0, 0, 1))
	require.NoError(t, err)
	assert.Equal(t, net.IPv4(10, 0, 0, 1).To4(), net.IP(a2.Value))

	_, err = NewByName(d, "NAS-IP-Address", "not-an-ip")
	require.Error(t, err)
}

func TestNewByName_IPv6(t *testing.T) {
	d := dictionary.Default()

	a, err := NewByName(d, "NAS-IPv6-Address", "2001:db8::1")
	require.NoError(t, err)
	assert.Len(t, a.Value, 16)
	assert.Equal(t, net.ParseIP("2001:db8::1").To16(), net.IP(a.Value))
}

func TestNewByName_Unknown(t *testing.T) {
	d := dictionary.Default()
	_, err := NewByName(d, "Not-An-Attribute", "x")
	require.ErrorIs(t, err, errors.ErrUnknownAttribute)
}

func TestNewByName_UnsupportedType(t *testing.T) {
	d := dictionary.Default()
	_, err := NewByName(d, "Vendor-Specific", "x")
	require.ErrorIs(t, err, errors.ErrUnsupportedValueType)
}

func TestMustNewByName_Panics(t *testing.T) {
	d := dictionary.Default()
	assert.Panics(t, func() {
		MustNewByName(d, "Unknown", "x")
	})
}

func TestMustNewByName_OK(t *testing.T) {
	d := dictionary.Default()
	a := MustNewByName(d, "User-Name", "alice")
	assert.Equal(t, "alice", string(a.Value))
}

func TestPacket_GetByName(t *testing.T) {
	d := dictionary.Default()
	p := &Packet{
		Attributes: []Attribute{
			NewString(types.AttrUserName, "alice"),
			NewString(types.AttrUserName, "alice2"),
			NewInteger(types.AttrNASPort, 10),
		},
	}

	got := p.GetByName(d, "User-Name")
	require.Len(t, got, 2)
	assert.Equal(t, "alice", string(got[0].Value))

	one, ok := p.GetOneByName(d, "NAS-Port")
	require.True(t, ok)
	n, err := one.Integer()
	require.NoError(t, err)
	assert.Equal(t, uint32(10), n)

	_, ok = p.GetOneByName(d, "Unknown")
	assert.False(t, ok)
}

func TestAttribute_Decode(t *testing.T) {
	d := dictionary.Default()

	t.Run("string", func(t *testing.T) {
		a := NewString(types.AttrUserName, "alice")
		v, err := a.Decode(d)
		require.NoError(t, err)
		assert.Equal(t, "alice", v)
	})

	t.Run("integer", func(t *testing.T) {
		a := NewInteger(types.AttrNASPort, 254)
		v, err := a.Decode(d)
		require.NoError(t, err)
		assert.Equal(t, uint32(254), v)
	})

	t.Run("ipv4", func(t *testing.T) {
		a := NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 1, 2, 3))
		v, err := a.Decode(d)
		require.NoError(t, err)
		ip, ok := v.(net.IP)
		require.True(t, ok)
		assert.Equal(t, net.IPv4(10, 1, 2, 3).To4(), ip.To4())
	})

	t.Run("ipv6", func(t *testing.T) {
		a := NewIPv6Addr(types.AttrNASIPv6Address, net.ParseIP("2001:db8::1"))
		v, err := a.Decode(d)
		require.NoError(t, err)
		ip, ok := v.(net.IP)
		require.True(t, ok)
		assert.Len(t, ip, 16)
	})

	t.Run("vsa", func(t *testing.T) {
		a := NewVendorSpecific(9, []byte{0x01, 0x02})
		v, err := a.Decode(d)
		require.NoError(t, err)
		vsa, ok := v.(*VSAValue)
		require.True(t, ok)
		assert.Equal(t, uint32(9), vsa.VendorID)
		assert.Equal(t, []byte{0x01, 0x02}, vsa.Data)
	})

	t.Run("unknown type", func(t *testing.T) {
		a := Attribute{Type: 200, Value: []byte{0x01}}
		_, err := a.Decode(d)
		require.ErrorIs(t, err, errors.ErrUnknownAttribute)
	})
}

func TestAttribute_DecodeString_Integer(t *testing.T) {
	d := dictionary.Default()
	a := NewInteger(types.AttrNASPort, 1)
	_, err := a.DecodeString(d)
	require.ErrorIs(t, err, errors.ErrInvalidAttribute)
}

func TestAttribute_DecodeInteger_String(t *testing.T) {
	d := dictionary.Default()
	a := NewString(types.AttrUserName, "alice")
	_, err := a.DecodeInteger(d)
	require.ErrorIs(t, err, errors.ErrInvalidAttribute)
}
