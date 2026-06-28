package packet

import (
	"fmt"
	"math"
	"net"
	"strconv"

	"github.com/wxccs/radius/v2/dictionary"
	radiuserrors "github.com/wxccs/radius/v2/errors"
)

// VSAValue is the decoded form of a Vendor-Specific attribute (Type 26).
// Returned by Attribute.Decode when the dictionary declares the attribute's
// ValueType as TypeVSA.
type VSAValue struct {
	VendorID uint32
	Data     []byte
}

// NewByName constructs an Attribute by canonical name (e.g. "User-Name").
// The dictionary's ValueType for the named attribute decides how value is
// encoded:
//
//   - TypeString, TypeOctets, TypeRaw: value must be string, []byte, or fmt.Stringer
//   - TypeInteger:                      value must be uint32, uint, int, or a numeric string
//   - TypeIPAddr:                        value must be net.IP or an IPv4 string
//   - TypeIPv6Addr:                      value must be net.IP or an IPv6 string
//   - TypeVSA, TypeExtended:             not supported (returns ErrUnsupportedValueType)
//
// TypeRaw is treated identically to TypeOctets so attributes loaded from
// FreeRADIUS dictionaries whose type has no runtime codec can still be
// carried on the wire as opaque bytes.
//
// Returns ErrUnknownAttribute when name is not registered in dict.
func NewByName(dict *dictionary.Dictionary, name string, value any) (Attribute, error) {
	def, ok := dict.LookupName(name)
	if !ok {
		return Attribute{}, fmt.Errorf("%w: %q", radiuserrors.ErrUnknownAttribute, name)
	}
	switch def.ValueType {
	case dictionary.TypeString, dictionary.TypeOctets, dictionary.TypeRaw:
		b, err := toStringBytes(value)
		if err != nil {
			return Attribute{}, fmt.Errorf("radius: attribute %q: %w", name, err)
		}
		return Attribute{Type: def.Type, Value: b}, nil
	case dictionary.TypeInteger:
		n, err := toUint32(value)
		if err != nil {
			return Attribute{}, fmt.Errorf("radius: attribute %q: %w", name, err)
		}
		return NewInteger(def.Type, n), nil
	case dictionary.TypeIPAddr:
		ip, err := toIPv4(value)
		if err != nil {
			return Attribute{}, fmt.Errorf("radius: attribute %q: %w", name, err)
		}
		return NewIPAddr(def.Type, ip), nil
	case dictionary.TypeIPv6Addr:
		ip, err := toIPv6(value)
		if err != nil {
			return Attribute{}, fmt.Errorf("radius: attribute %q: %w", name, err)
		}
		return NewIPv6Addr(def.Type, ip), nil
	default:
		return Attribute{}, fmt.Errorf("%w: %s for %q",
			radiuserrors.ErrUnsupportedValueType, def.ValueType, name)
	}
}

// MustNewByName panics if NewByName returns an error. Intended for
// package-level variable initialization; not for request paths.
func MustNewByName(dict *dictionary.Dictionary, name string, value any) Attribute {
	a, err := NewByName(dict, name, value)
	if err != nil {
		panic(err)
	}
	return a
}

// GetByName returns all attributes matching the named type, in packet order.
// Returns nil when name is unknown or no attribute of that type is present.
func (p *Packet) GetByName(dict *dictionary.Dictionary, name string) []Attribute {
	def, ok := dict.LookupName(name)
	if !ok {
		return nil
	}
	return p.Get(def.Type)
}

// GetOneByName returns the first attribute matching the named type and true,
// or Attribute{} / false when the name is unknown or no such attribute is
// present.
func (p *Packet) GetOneByName(dict *dictionary.Dictionary, name string) (Attribute, bool) {
	def, ok := dict.LookupName(name)
	if !ok {
		return Attribute{}, false
	}
	return p.GetOne(def.Type)
}

// Decode returns the typed value of a using the dictionary's ValueType for
// a.Type. The returned types are:
//
//   - TypeString: string
//   - TypeOctets, TypeRaw: []byte (a copy)
//   - TypeInteger: uint32
//   - TypeIPAddr: net.IP (4-byte)
//   - TypeIPv6Addr: net.IP (16-byte)
//   - TypeVSA: *VSAValue
//   - TypeExtended: not supported
//
// TypeRaw is decoded as []byte (a copy of a.Value) so attributes loaded
// from FreeRADIUS dictionaries whose type has no runtime codec can still
// be inspected as raw bytes.
//
// Returns ErrUnknownAttribute when a.Type is not registered in dict.
func (a Attribute) Decode(dict *dictionary.Dictionary) (any, error) {
	def, ok := dict.Lookup(a.Type)
	if !ok {
		return nil, fmt.Errorf("%w: type %d", radiuserrors.ErrUnknownAttribute, a.Type)
	}
	switch def.ValueType {
	case dictionary.TypeString:
		return string(a.Value), nil
	case dictionary.TypeOctets, dictionary.TypeRaw:
		return append([]byte(nil), a.Value...), nil
	case dictionary.TypeInteger:
		return a.Integer()
	case dictionary.TypeIPAddr:
		return a.IPAddr()
	case dictionary.TypeIPv6Addr:
		return a.IPv6Addr()
	case dictionary.TypeVSA:
		vendorID, data, err := a.VendorSpecific()
		if err != nil {
			return nil, err
		}
		return &VSAValue{VendorID: vendorID, Data: append([]byte(nil), data...)}, nil
	default:
		return nil, fmt.Errorf("%w: %s", radiuserrors.ErrUnsupportedValueType, def.ValueType)
	}
}

// DecodeString is a convenience for Decode when the caller knows the
// attribute carries a string. Returns ErrInvalidAttribute if the
// dictionary declares a non-string ValueType for a.Type.
func (a Attribute) DecodeString(dict *dictionary.Dictionary) (string, error) {
	def, ok := dict.Lookup(a.Type)
	if !ok {
		return "", fmt.Errorf("%w: type %d", radiuserrors.ErrUnknownAttribute, a.Type)
	}
	if def.ValueType != dictionary.TypeString {
		return "", fmt.Errorf("%w: expected string, got %s",
			radiuserrors.ErrInvalidAttribute, def.ValueType)
	}
	return string(a.Value), nil
}

// DecodeInteger is a convenience for Decode when the caller knows the
// attribute carries a 4-byte integer.
func (a Attribute) DecodeInteger(dict *dictionary.Dictionary) (uint32, error) {
	def, ok := dict.Lookup(a.Type)
	if !ok {
		return 0, fmt.Errorf("%w: type %d", radiuserrors.ErrUnknownAttribute, a.Type)
	}
	if def.ValueType != dictionary.TypeInteger {
		return 0, fmt.Errorf("%w: expected integer, got %s",
			radiuserrors.ErrInvalidAttribute, def.ValueType)
	}
	return a.Integer()
}

// toStringBytes coerces value into a fresh []byte using the rules documented
// on NewByName.
func toStringBytes(value any) ([]byte, error) {
	switch v := value.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return append([]byte(nil), v...), nil
	case fmt.Stringer:
		return []byte(v.String()), nil
	default:
		return nil, fmt.Errorf("value of type %T is not a string or []byte", value)
	}
}

// toUint32 coerces value into a uint32 using the rules documented on
// NewByName.
func toUint32(value any) (uint32, error) {
	switch v := value.(type) {
	case uint32:
		return v, nil
	case uint:
		if uint64(v) > math.MaxUint32 {
			return 0, fmt.Errorf("value %d overflows uint32", v)
		}
		return uint32(v), nil
	case int:
		if v < 0 || int64(v) > math.MaxUint32 {
			return 0, fmt.Errorf("value %d out of uint32 range", v)
		}
		return uint32(v), nil
	case string:
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid integer %q: %w", v, err)
		}
		return uint32(n), nil
	default:
		return 0, fmt.Errorf("value of type %T is not an integer", value)
	}
}

// toIPv4 coerces value into a 4-byte net.IP.
func toIPv4(value any) (net.IP, error) {
	ip, err := parseIP(value)
	if err != nil {
		return nil, err
	}
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...), nil
	}
	return nil, fmt.Errorf("value %v is not an IPv4 address", value)
}

// toIPv6 coerces value into a 16-byte net.IP.
func toIPv6(value any) (net.IP, error) {
	ip, err := parseIP(value)
	if err != nil {
		return nil, err
	}
	if v6 := ip.To16(); v6 != nil {
		return append(net.IP(nil), v6...), nil
	}
	return nil, fmt.Errorf("value %v is not an IPv6 address", value)
}

// parseIP accepts net.IP and string inputs. Strings are parsed with
// net.ParseIP; both IPv4 and IPv6 forms are accepted.
func parseIP(value any) (net.IP, error) {
	switch v := value.(type) {
	case net.IP:
		return v, nil
	case string:
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", v)
		}
		return ip, nil
	default:
		return nil, fmt.Errorf("value of type %T is not an IP address", value)
	}
}
