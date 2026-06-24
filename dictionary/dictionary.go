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

// Package dictionary maps RADIUS attribute type numbers to human-readable
// metadata: the attribute name, the wire encoding of its Value (string,
// integer, IP address, raw octets, vendor-specific, or RFC 6929 extended),
// whether the value is encrypted on the wire, and whether it carries an
// RFC 2868 tag.
//
// A single global Dictionary is initialized at package load time with the
// standard attributes defined by RFC 2865 and RFC 2866. Callers may register
// additional attributes (vendor-specific, site-specific, or future RFCs) into
// the default dictionary, or construct isolated Dictionary instances with
// New() for testing or for parallel use of conflicting schemas.
//
// The dictionary performs no encoding or decoding of attribute values itself;
// it only describes them so that callers can dispatch to the correct codec.
package dictionary

import (
	"errors"
	"fmt"
	"sync"

	radiuserrors "github.com/wxccs/radius/errors"
)

// ValueType describes how an attribute's Value field is encoded on the wire.
type ValueType int

const (
	// TypeString is a UTF-8 octet string (RFC 2865 §5).
	TypeString ValueType = iota
	// TypeInteger is a 4-byte big-endian unsigned integer.
	TypeInteger
	// TypeIPAddr is a 4-byte IPv4 address.
	TypeIPAddr
	// TypeIPv6Addr is a 16-byte IPv6 address (RFC 3162).
	TypeIPv6Addr
	// TypeOctets is a raw octet string with no implied interpretation.
	TypeOctets
	// TypeVSA marks a Vendor-Specific attribute (Type 26) whose Value begins
	// with a 4-byte Vendor-Id followed by vendor-defined data.
	TypeVSA
	// TypeExtended marks an RFC 6929 extended attribute.
	TypeExtended
)

// String returns the canonical name of the value type.
func (v ValueType) String() string {
	switch v {
	case TypeString:
		return "string"
	case TypeInteger:
		return "integer"
	case TypeIPAddr:
		return "ipaddr"
	case TypeIPv6Addr:
		return "ipv6addr"
	case TypeOctets:
		return "octets"
	case TypeVSA:
		return "vsa"
	case TypeExtended:
		return "extended"
	}
	return "unknown"
}

// AttributeDef describes a single attribute's wire format. A Dictionary maps
// Type numbers and Names to AttributeDef pointers.
type AttributeDef struct {
	// Type is the 1-byte attribute type number (1..255).
	Type byte
	// Name is the canonical attribute name with hyphens, e.g. "User-Name".
	Name string
	// ValueType selects the wire encoding of the Value field.
	ValueType ValueType
	// Encrypt is 0 for cleartext attributes and 1 for User-Password-style
	// attributes whose Value is hidden using the RFC 2865 §5.2 algorithm.
	// Other values are reserved for future RFCs.
	Encrypt int
	// HasTag is true for RFC 2868 tagged attributes. Tagged attribute
	// encoding/decoding is handled by the crypto package (EncodeTunnelTag /
	// DecodeTunnelTag).
	HasTag bool
}

// Dictionary maps attribute Type numbers and Names to AttributeDef entries.
// All methods are safe for concurrent use.
type Dictionary struct {
	mu     sync.RWMutex
	byType map[byte]*AttributeDef
	byName map[string]*AttributeDef
}

// New returns an empty Dictionary. The caller owns the returned instance and
// may Register into it without affecting the global default dictionary.
func New() *Dictionary {
	return &Dictionary{
		byType: make(map[byte]*AttributeDef),
		byName: make(map[string]*AttributeDef),
	}
}

// Register stores def in the dictionary, indexed by both Type and Name.
// A subsequent Register with the same Type overwrites the prior entry and
// updates the Name index accordingly. Returns ErrInvalidAttribute if Name
// is empty.
func (d *Dictionary) Register(def AttributeDef) error {
	if def.Name == "" {
		return fmt.Errorf("%w: attribute name is empty", radiuserrors.ErrInvalidAttribute)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	// Remove the previous name binding if this Type was registered under a
	// different Name, so that LookupName cannot return a stale entry.
	if existing, ok := d.byType[def.Type]; ok && existing.Name != def.Name {
		delete(d.byName, existing.Name)
	}
	// If the Name is already bound to a different Type, drop the old Type
	// binding so that Lookup stays consistent.
	if existing, ok := d.byName[def.Name]; ok && existing.Type != def.Type {
		delete(d.byType, existing.Type)
	}

	entry := def
	d.byType[def.Type] = &entry
	d.byName[def.Name] = &entry
	return nil
}

// Lookup returns the AttributeDef for the given Type and true, or false if no
// attribute with that Type has been registered.
func (d *Dictionary) Lookup(t byte) (*AttributeDef, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	def, ok := d.byType[t]
	return def, ok
}

// LookupName returns the AttributeDef for the given Name and true, or false if
// no attribute with that Name has been registered.
func (d *Dictionary) LookupName(name string) (*AttributeDef, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	def, ok := d.byName[name]
	return def, ok
}

// Size returns the number of attribute definitions currently registered.
func (d *Dictionary) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.byType)
}

// defaultDict is the singleton Dictionary initialized at package load time
// with the RFC 2865 and RFC 2866 standard attributes.
var (
	defaultDict     = New()
	defaultDictOnce sync.Once
)

// Default returns the shared dictionary that init() has populated with the
// standard RFC 2865 and RFC 2866 attributes. Callers may Register additional
// attributes into it; for test isolation, use ResetForTest followed by
// re-registration, or construct a fresh Dictionary via New().
func Default() *Dictionary {
	defaultDictOnce.Do(func() {})
	return defaultDict
}

// Register adds def to the default dictionary. See Dictionary.Register for
// semantics.
func Register(def AttributeDef) error {
	return defaultDict.Register(def)
}

// ResetForTest clears all entries from the default dictionary. As the name
// implies this is intended for use in tests that need to assert behavior with
// an empty or re-seeded dictionary; production code should not call it.
func ResetForTest() {
	defaultDict.mu.Lock()
	defer defaultDict.mu.Unlock()
	defaultDict.byType = make(map[byte]*AttributeDef)
	defaultDict.byName = make(map[string]*AttributeDef)
}

// registerStandardAttributes seeds the default dictionary with all RFC-defined
// standard attributes. Called once from init; tests that call ResetForTest
// use this to restore the dictionary to a known-good state.
func registerStandardAttributes() {
	registerRFC2865()
	registerRFC2866()
	registerRFC2868()
	registerRFC2869()
	registerRFC3162()
	registerRFC5176()
	registerRFC6929()
}

// init seeds the default dictionary with the standard attributes defined by
// RFC 2865 (RADIUS base), RFC 2866 (Accounting), RFC 2868 (Tunnel), RFC 2869
// (Extensions), RFC 3162 (IPv6), RFC 5176 (Dynamic Authorization) and
// RFC 6929 (Extended Attributes). Vendor-specific attributes are added by
// callers as needed.
//
// RFC 2867 (Tunnel Accounting) and RFC 9445 (Packet Type Issues) do not
// define new attribute types: RFC 2867 specifies how tunnel attributes
// appear in Accounting-Request packets, and RFC 9445 clarifies
// Code/Identifier/Length semantics. Both are therefore represented here by
// documentation only.
func init() {
	registerStandardAttributes()
}

// registerRFC2865 registers the standard attributes from RFC 2865 §5.
func registerRFC2865() {
	defs := []AttributeDef{
		{Type: 1, Name: "User-Name", ValueType: TypeString},
		{Type: 2, Name: "User-Password", ValueType: TypeString, Encrypt: 1},
		{Type: 3, Name: "CHAP-Password", ValueType: TypeOctets},
		{Type: 4, Name: "NAS-IP-Address", ValueType: TypeIPAddr},
		{Type: 5, Name: "NAS-Port", ValueType: TypeInteger},
		{Type: 6, Name: "Service-Type", ValueType: TypeInteger},
		{Type: 7, Name: "Framed-Protocol", ValueType: TypeInteger},
		{Type: 8, Name: "Framed-IP-Address", ValueType: TypeIPAddr},
		{Type: 9, Name: "Framed-IP-Netmask", ValueType: TypeIPAddr},
		{Type: 10, Name: "Framed-Routing", ValueType: TypeInteger},
		{Type: 11, Name: "Filter-Id", ValueType: TypeString},
		{Type: 12, Name: "Framed-MTU", ValueType: TypeInteger},
		{Type: 13, Name: "Framed-Compression", ValueType: TypeInteger},
		{Type: 14, Name: "Login-IP-Host", ValueType: TypeIPAddr},
		{Type: 15, Name: "Login-Service", ValueType: TypeInteger},
		{Type: 16, Name: "Login-TCP-Port", ValueType: TypeInteger},
		{Type: 18, Name: "Reply-Message", ValueType: TypeString},
		{Type: 19, Name: "Callback-Number", ValueType: TypeString},
		{Type: 20, Name: "Callback-Id", ValueType: TypeString},
		{Type: 22, Name: "Framed-Route", ValueType: TypeString},
		{Type: 23, Name: "Framed-IPX-Network", ValueType: TypeInteger},
		{Type: 24, Name: "State", ValueType: TypeOctets},
		{Type: 25, Name: "Class", ValueType: TypeOctets},
		{Type: 26, Name: "Vendor-Specific", ValueType: TypeVSA},
		{Type: 27, Name: "Session-Timeout", ValueType: TypeInteger},
		{Type: 28, Name: "Idle-Timeout", ValueType: TypeInteger},
		{Type: 29, Name: "Termination-Action", ValueType: TypeInteger},
		{Type: 30, Name: "Called-Station-Id", ValueType: TypeString},
		{Type: 31, Name: "Calling-Station-Id", ValueType: TypeString},
		{Type: 32, Name: "NAS-Identifier", ValueType: TypeString},
		{Type: 33, Name: "Proxy-State", ValueType: TypeOctets},
		{Type: 34, Name: "Login-LAT-Service", ValueType: TypeString},
		{Type: 35, Name: "Login-LAT-Node", ValueType: TypeString},
		{Type: 36, Name: "Login-LAT-Group", ValueType: TypeString},
		{Type: 37, Name: "Framed-AppleTalk-Link", ValueType: TypeInteger},
		{Type: 38, Name: "Framed-AppleTalk-Network", ValueType: TypeInteger},
		{Type: 39, Name: "Framed-AppleTalk-Zone", ValueType: TypeString},
		{Type: 60, Name: "CHAP-Challenge", ValueType: TypeOctets},
		{Type: 61, Name: "NAS-Port-Type", ValueType: TypeInteger},
		{Type: 62, Name: "Port-Limit", ValueType: TypeInteger},
		{Type: 63, Name: "Login-LAT-Port", ValueType: TypeString},
	}
	for _, def := range defs {
		if err := defaultDict.Register(def); err != nil {
			panic(errors.New("dictionary: failed to register RFC 2865 attribute " + def.Name))
		}
	}
}

// registerRFC2866 registers the accounting attributes from RFC 2866 §5.
func registerRFC2866() {
	defs := []AttributeDef{
		{Type: 40, Name: "Acct-Status-Type", ValueType: TypeInteger},
		{Type: 41, Name: "Acct-Delay-Time", ValueType: TypeInteger},
		{Type: 42, Name: "Acct-Input-Octets", ValueType: TypeInteger},
		{Type: 43, Name: "Acct-Output-Octets", ValueType: TypeInteger},
		{Type: 44, Name: "Acct-Session-Id", ValueType: TypeString},
		{Type: 45, Name: "Acct-Authentic", ValueType: TypeInteger},
		{Type: 46, Name: "Acct-Session-Time", ValueType: TypeInteger},
		{Type: 47, Name: "Acct-Input-Packets", ValueType: TypeInteger},
		{Type: 48, Name: "Acct-Output-Packets", ValueType: TypeInteger},
		{Type: 49, Name: "Acct-Terminate-Cause", ValueType: TypeInteger},
		{Type: 50, Name: "Acct-Multi-Session-Id", ValueType: TypeString},
		{Type: 51, Name: "Acct-Link-Count", ValueType: TypeInteger},
	}
	for _, def := range defs {
		if err := defaultDict.Register(def); err != nil {
			panic(errors.New("dictionary: failed to register RFC 2866 attribute " + def.Name))
		}
	}
}
