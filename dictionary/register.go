package dictionary

import (
	"fmt"

	"github.com/wxccs/radius/dictionary/parser"
)

// RegisterFromDict merges every entry from p into d. Attributes are
// registered via Register (last-write-wins on Type or Name collision).
// Unknown FreeRADIUS value types — those normalized to "raw" by the
// parser — are mapped to TypeRaw so callers can still round-trip them
// as opaque octets without rejecting the entire dictionary.
//
// Vendor entries and VALUE enumerations are recorded but do not affect
// the runtime codec directly; they are surfaced here so that callers
// building vendor-specific packages or code generators have a single
// entry point for loading a FreeRADIUS dictionary file.
func (d *Dictionary) RegisterFromDict(p *parser.Dict) error {
	if p == nil {
		return nil
	}
	for _, attr := range p.Attributes {
		vt, err := mapValueType(attr.ValueType)
		if err != nil {
			return fmt.Errorf("attribute %s: %w", attr.Name, err)
		}
		def := AttributeDef{
			Type:      attr.Type,
			Name:      attr.Name,
			ValueType: vt,
			Encrypt:   attr.Encrypt,
			HasTag:    attr.HasTag,
		}
		if err := d.Register(def); err != nil {
			return fmt.Errorf("register attribute %s: %w", attr.Name, err)
		}
	}
	return nil
}

// mapValueType translates the parser's string-form value type into the
// runtime ValueType enum. The string forms are produced by
// parser.normalizeValueType.
func mapValueType(s string) (ValueType, error) {
	switch s {
	case "string":
		return TypeString, nil
	case "integer":
		return TypeInteger, nil
	case "ipaddr":
		return TypeIPAddr, nil
	case "ipv6addr":
		return TypeIPv6Addr, nil
	case "octets":
		return TypeOctets, nil
	case "vsa":
		return TypeVSA, nil
	case "extended":
		return TypeExtended, nil
	case "raw":
		return TypeRaw, nil
	case "":
		// Treat an empty type token as raw so a malformed dictionary
		// entry still loads with degraded behavior.
		return TypeRaw, nil
	default:
		return 0, fmt.Errorf("unknown value type %q", s)
	}
}
