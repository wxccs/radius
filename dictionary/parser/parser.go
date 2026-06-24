// Package parser reads FreeRADIUS-format dictionary files and produces a
// Dict — a pure data structure describing attributes, enum values, and
// vendors. The parser has no dependency on the runtime dictionary so the
// same *Dict can be consumed by code generators as well as by the
// runtime Dictionary.RegisterFromDict method.
//
// Supported directives:
//
//	# comment                        (to end of line)
//	$INCLUDE path                    (relative to the current file)
//	ATTRIBUTE name number type [flags]
//	VALUE attribute-name value-name number
//	VENDOR name id
//	BEGIN-VENDOR vendor-name
//	END-VENDOR
//	ALIAS attr-name alias-name
//
// Attribute type tokens understood by this parser are mapped to the
// string forms used by dictionary.ValueType (string, integer, ipaddr,
// ipv6addr, octets, vsa, extended). Tokens that have no runtime codec
// (ifid, ipv6prefix, tlvs, byte, short, signed, date, abinary, combo-ip,
// ...) are normalized to "raw" so the runtime Dictionary can downgrade
// them to TypeRaw instead of rejecting the whole file.
package parser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Dict is the in-memory representation of one or more FreeRADIUS dictionary
// files. It is a pure data structure: callers may mutate it freely and pass
// it to dictionary.Dictionary.RegisterFromDict for runtime use, or walk it
// for code generation.
type Dict struct {
	Attributes []Attr
	Values     []Val
	Vendors    []Vendor
}

// Attr describes a single ATTRIBUTE entry. Vendor is the empty string for
// standard (RFC) attributes; for VSA sub-attributes it is the vendor name
// declared by the surrounding BEGIN-VENDOR block.
type Attr struct {
	Name      string
	Type      byte
	ValueType string
	Encrypt   int
	HasTag    bool
	Vendor    string
}

// Val describes a single VALUE entry: an enumeration name bound to a
// number for a parent attribute.
type Val struct {
	AttributeName string
	Name          string
	Number        uint64
}

// Vendor describes a single VENDOR entry mapping a human-readable name
// to the 4-byte Vendor-Id carried on the wire inside Vendor-Specific.
type Vendor struct {
	Name string
	ID   uint32
}

// Parse reads a single dictionary from r, returning a *Dict that contains
// every entry in source order. $INCLUDE directives are not resolved when
// parsing from an io.Reader (the base directory is unknown); use ParseFile
// to enable $INCLUDE handling.
func Parse(r io.Reader) (*Dict, error) {
	return parse(r, "", nil)
}

// ParseFile reads the dictionary at path, resolving $INCLUDE directives
// relative to path's directory. Cycles in the include graph are detected
// and reported as an error.
func ParseFile(path string) (*Dict, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", path, err)
	}
	visited := map[string]bool{}
	return parseFile(abs, visited)
}

// ParseFiles reads one or more dictionary files, merging them into a
// single *Dict. Files are parsed in order; later files may override
// earlier ones via Dictionary.RegisterFromDict semantics (last write wins).
func ParseFiles(paths ...string) (*Dict, error) {
	merged := &Dict{}
	for _, p := range paths {
		d, err := ParseFile(p)
		if err != nil {
			return nil, err
		}
		merged.Attributes = append(merged.Attributes, d.Attributes...)
		merged.Values = append(merged.Values, d.Values...)
		merged.Vendors = append(merged.Vendors, d.Vendors...)
	}
	return merged, nil
}

// parseFile is the recursive worker for ParseFile. visited tracks the
// absolute paths currently on the include stack so a cycle (a.dict
// includes b.dict includes a.dict) is reported with the chain.
func parseFile(abs string, visited map[string]bool) (*Dict, error) {
	if visited[abs] {
		return nil, fmt.Errorf("circular $INCLUDE detected at %s", abs)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	visited[abs] = true
	defer delete(visited, abs)
	return parse(f, filepath.Dir(abs), visited)
}

// parse is the shared core. baseDir is the directory used to resolve
// $INCLUDE directives (empty when parsing from an io.Reader with no
// known base). visited is the active include stack.
func parse(r io.Reader, baseDir string, visited map[string]bool) (*Dict, error) {
	d := &Dict{}
	p := &parser{d: d, baseDir: baseDir, visited: visited}
	sc := bufio.NewScanner(r)
	// Allow long lines: dictionary entries can carry many flags.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		if err := p.line(raw, lineNo); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return d, nil
}

type parser struct {
	d       *Dict
	baseDir string
	visited map[string]bool

	// vendorCtx is the vendor name when inside a BEGIN-VENDOR block,
	// or empty when outside.
	vendorCtx string
}

// line processes one input line. Comments and blank lines are ignored.
// Directive tokens are dispatched to the matching handler.
func (p *parser) line(raw string, lineNo int) error {
	// Strip trailing comments. A '#' that begins a token mid-line is
	// preserved (e.g. inside a quoted attribute name), but a '#' that
	// begins a word is treated as a comment marker.
	line := stripComment(raw)
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	directive := fields[0]
	args := fields[1:]
	switch directive {
	case "$INCLUDE":
		return p.handleInclude(args, lineNo)
	case "ATTRIBUTE":
		return p.handleAttribute(args, lineNo)
	case "VALUE":
		return p.handleValue(args, lineNo)
	case "VENDOR":
		return p.handleVendor(args, lineNo)
	case "BEGIN-VENDOR":
		return p.handleBeginVendor(args, lineNo)
	case "END-VENDOR":
		p.vendorCtx = ""
		return nil
	case "ALIAS":
		// Aliases are informational for code generation; ignored at
		// runtime so they don't affect the dictionary.
		return nil
	case "BEGIN-TLV", "END-TLV", "BEGIN-ENUM", "END-ENUM":
		// FreeRADIUS structural markers for nested TLV / enum
		// dictionaries. The runtime codec treats nested TLVs as raw
		// octets, so we don't need to model their nesting here.
		return nil
	default:
		// Unknown directives are tolerated to keep the parser
		// forward-compatible; emit no error so a single new token in
		// an upstream dictionary does not break parsing.
		return nil
	}
}

// stripComment removes the trailing portion of raw starting at the first
// '#' that begins a word. Quoted '#' inside a token (rare) is preserved.
func stripComment(raw string) string {
	// Fast path: no '#' at all.
	if !strings.ContainsRune(raw, '#') {
		return raw
	}
	// Walk rune by rune so we only strip when '#' is preceded by
	// whitespace or begins the line.
	r := []rune(raw)
	inQuote := false
	for i := range r {
		c := r[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		if c == '#' && (i == 0 || r[i-1] == ' ' || r[i-1] == '\t') {
			return string(r[:i])
		}
	}
	return raw
}

func (p *parser) handleInclude(args []string, lineNo int) error {
	if len(args) != 1 {
		return fmt.Errorf("line %d: $INCLUDE expects exactly one path, got %d", lineNo, len(args))
	}
	if p.baseDir == "" {
		return fmt.Errorf("line %d: $INCLUDE requires ParseFile (no base directory available for Parse)", lineNo)
	}
	inc := args[0]
	if !filepath.IsAbs(inc) {
		inc = filepath.Join(p.baseDir, inc)
	}
	abs, err := filepath.Abs(inc)
	if err != nil {
		return fmt.Errorf("line %d: resolve $INCLUDE %s: %w", lineNo, inc, err)
	}
	sub, err := parseFile(abs, p.visited)
	if err != nil {
		return fmt.Errorf("line %d: $INCLUDE %s: %w", lineNo, inc, err)
	}
	p.d.Attributes = append(p.d.Attributes, sub.Attributes...)
	p.d.Values = append(p.d.Values, sub.Values...)
	p.d.Vendors = append(p.d.Vendors, sub.Vendors...)
	return nil
}

func (p *parser) handleAttribute(args []string, lineNo int) error {
	if len(args) < 3 {
		return fmt.Errorf("line %d: ATTRIBUTE expects name number type [flags], got %d fields", lineNo, len(args))
	}
	name := args[0]
	typeNum, err := parseAttrNumber(args[1])
	if err != nil {
		return fmt.Errorf("line %d: ATTRIBUTE %s: %w", lineNo, name, err)
	}
	valueType := normalizeValueType(args[2])
	attr := Attr{
		Name:      name,
		Type:      typeNum,
		ValueType: valueType,
		Vendor:    p.vendorCtx,
	}
	for _, flag := range args[3:] {
		if err := applyAttrFlag(&attr, flag); err != nil {
			return fmt.Errorf("line %d: ATTRIBUTE %s: %w", lineNo, name, err)
		}
	}
	p.d.Attributes = append(p.d.Attributes, attr)
	return nil
}

// parseAttrNumber accepts decimal, 0x-prefixed hex, or octal as Go's
// strconv.ParseUint with base=0 understands them.
func parseAttrNumber(s string) (byte, error) {
	n, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid attribute number %q: %w", s, err)
	}
	if n > 255 {
		return 0, fmt.Errorf("attribute number %d out of byte range", n)
	}
	return byte(n), nil
}

// normalizeValueType maps a FreeRADIUS type token to one of the string
// keys understood by dictionary.ValueType. Unknown tokens become "raw".
func normalizeValueType(token string) string {
	switch token {
	case "string", "text":
		return "string"
	case "integer":
		return "integer"
	case "ipaddr", "ipv4addr":
		return "ipaddr"
	case "ipv6addr":
		return "ipv6addr"
	case "octets", "octet", "abinary":
		return "octets"
	case "vsa":
		return "vsa"
	case "extended":
		return "extended"
	default:
		// ifid, ipv6prefix, byte, short, signed, date, tlvs, tlv,
		// combo-ip, etc. all map to "raw" so the runtime Dictionary
		// can mark the attribute as TypeRaw.
		return "raw"
	}
}

// applyAttrFlag parses a single ATTRIBUTE flag token (e.g. "encrypt=1",
// "has_tag", "array") and updates attr accordingly. Unknown flags are
// tolerated to remain forward-compatible with future FreeRADIUS tokens.
func applyAttrFlag(attr *Attr, flag string) error {
	if flag == "has_tag" {
		attr.HasTag = true
		return nil
	}
	if rest, ok := strings.CutPrefix(flag, "encrypt="); ok {
		v, err := strconv.Atoi(rest)
		if err != nil {
			return fmt.Errorf("invalid encrypt flag %q: %w", flag, err)
		}
		attr.Encrypt = v
		return nil
	}
	// array, concat, has_ref, etc. are accepted but have no runtime
	// effect on this library's codecs.
	return nil
}

func (p *parser) handleValue(args []string, lineNo int) error {
	if len(args) != 3 {
		return fmt.Errorf("line %d: VALUE expects attribute-name value-name number, got %d fields", lineNo, len(args))
	}
	n, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return fmt.Errorf("line %d: VALUE %s %s: invalid number %q: %w", lineNo, args[0], args[1], args[2], err)
	}
	p.d.Values = append(p.d.Values, Val{
		AttributeName: args[0],
		Name:          args[1],
		Number:        n,
	})
	return nil
}

func (p *parser) handleVendor(args []string, lineNo int) error {
	if len(args) < 2 {
		return fmt.Errorf("line %d: VENDOR expects name id, got %d fields", lineNo, len(args))
	}
	id, err := strconv.ParseUint(args[1], 0, 32)
	if err != nil {
		return fmt.Errorf("line %d: VENDOR %s: invalid id %q: %w", lineNo, args[0], args[1], err)
	}
	p.d.Vendors = append(p.d.Vendors, Vendor{Name: args[0], ID: uint32(id)})
	return nil
}

func (p *parser) handleBeginVendor(args []string, lineNo int) error {
	if len(args) != 1 {
		return fmt.Errorf("line %d: BEGIN-VENDOR expects exactly one vendor name, got %d", lineNo, len(args))
	}
	p.vendorCtx = args[0]
	return nil
}
