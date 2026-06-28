package packet

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/wxccs/radius/v2/dictionary"
	"github.com/wxccs/radius/v2/types"
)

// Format renders p as a multi-line human-readable string.
//
// When dict is non-nil and an attribute's Type is registered, the canonical
// name and a typed value interpretation are shown; otherwise the bare Type
// number and a hex dump are used. User-Password values are rendered as
// "<encrypted>" so the (already RFC 2865 §5.2 hidden) bytes are never echoed
// into logs.
//
// A nil *Packet renders as "<nil packet>".
func Format(p *Packet, dict *dictionary.Dictionary) string {
	if p == nil {
		return "<nil packet>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Code: %s (%d), ID: %d, Length: %d\n",
		p.Code.String(), p.Code, p.Identifier, types.PacketMinLength+sumAttrLen(p.Attributes))
	fmt.Fprintf(&b, "Authenticator: %s", hex.EncodeToString(p.Authenticator[:]))
	if len(p.Attributes) == 0 {
		return b.String()
	}
	b.WriteString("\nAttributes:")
	for _, a := range p.Attributes {
		fmt.Fprintf(&b, "\n  %s", FormatAttribute(a, dict))
	}
	return b.String()
}

// FormatAttribute renders a as a single line "Name (type) = value".
//
// When dict is nil or the Type is unknown, the name falls back to "<unknown>"
// and the value is shown as a hex string. User-Password is always masked.
func FormatAttribute(a Attribute, dict *dictionary.Dictionary) string {
	name := "<unknown>"
	if dict != nil {
		if def, ok := dict.Lookup(a.Type); ok {
			name = def.Name
		}
	}
	return fmt.Sprintf("%s (%d) = %s", name, a.Type, formatAttrValue(a, dict))
}

// formatAttrValue renders a's Value with dictionary-aware interpretation.
// User-Password is always masked regardless of dict.
func formatAttrValue(a Attribute, dict *dictionary.Dictionary) string {
	if a.Type == types.AttrUserPassword {
		return "<encrypted>"
	}
	if dict != nil {
		if def, ok := dict.Lookup(a.Type); ok {
			switch def.ValueType {
			case dictionary.TypeString:
				return strconv.Quote(string(a.Value))
			case dictionary.TypeInteger:
				if n, err := a.Integer(); err == nil {
					return strconv.FormatUint(uint64(n), 10)
				}
			case dictionary.TypeIPAddr:
				if ip, err := a.IPAddr(); err == nil {
					return ip.String()
				}
			case dictionary.TypeIPv6Addr:
				if ip, err := a.IPv6Addr(); err == nil {
					return ip.String()
				}
			case dictionary.TypeVSA:
				if vid, data, err := a.VendorSpecific(); err == nil {
					return fmt.Sprintf("vendor=%d data=%s", vid, hex.EncodeToString(data))
				}
			case dictionary.TypeOctets:
				return fmt.Sprintf("hex:%s", hex.EncodeToString(a.Value))
			}
		}
	}
	// No dictionary hint: guess by length for readability.
	switch len(a.Value) {
	case 4:
		if ip := net.IP(a.Value).To4(); ip != nil && isLikelyIPv4(a.Type) {
			return ip.String()
		}
		if n, err := a.Integer(); err == nil {
			return strconv.FormatUint(uint64(n), 10)
		}
	}
	return fmt.Sprintf("hex:%s", hex.EncodeToString(a.Value))
}

// isLikelyIPv4 reports whether the type number conventionally carries an
// IPv4 address, so the formatter can prefer dotted-quad rendering. The list
// is short on purpose; anything outside it falls through to integer/hex.
func isLikelyIPv4(t byte) bool {
	switch t {
	case types.AttrNASIPAddress,
		types.AttrFramedIPAddress,
		types.AttrFramedIPNetmask,
		types.AttrLoginIPHost:
		return true
	}
	return false
}

// sumAttrLen returns the total byte length of all attributes once marshaled
// (each attribute contributes 2 + len(Value) bytes).
func sumAttrLen(attrs []Attribute) int {
	total := 0
	for _, a := range attrs {
		total += 2 + len(a.Value)
		if len(a.Value) > types.AttrValueMaxLength {
			// Over-long attributes cannot marshal; report the declared length
			// so the formatter stays useful as a debugging aid.
			total = -1
			break
		}
	}
	return total
}
