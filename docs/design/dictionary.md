# Dictionary Layer Design

Status: implemented  
Scope: `dictionary/`, `dictionary/parser/`, `dictionary/gen/`,
`cmd/dict-gen/` — FreeRADIUS dictionary parsing, runtime registration,
and Go code generation.

## 1. Goals

- Parse the FreeRADIUS dictionary file format without depending on the
  FreeRADIUS codebase or its license.
- Bridge parsed dictionaries into the runtime `*Dictionary` registry so
  attributes can be looked up by name at runtime.
- Generate typed Go source (constants + accessor pairs) from a parsed
  dictionary so applications can reference attributes by name at
  compile time, with type-safe getters and setters.
- Be tolerant of unknown directives and value types — the parser must
  not fail on forward-compatible dictionary extensions.

## 2. Non-Goals

- Implementing codecs for every value type FreeRADIUS defines. Types
  without a runtime codec are marked as `TypeRaw` and treated as opaque
  bytes.
- Validating semantic correctness of the dictionary (e.g. duplicate
  attribute numbers, vendor sub-type collisions). The parser is
  permissive; validation is the caller's responsibility.
- Parsing FreeRADIUS's `update`/`$INCLUDE`-within-`BEGIN-VENDOR`
  conditional logic. The parser handles a flat, well-formed subset.

## 3. Package Layout

```
dictionary/
├── dictionary.go       # ValueType enum, *Dictionary registry
├── register.go         # RegisterFromDict bridges parser → runtime
├── rfc2868.go          # RFC 2868 attribute registrations
├── rfc2869.go          # RFC 2869 attribute registrations
├── rfc3162.go          # RFC 3162 IPv6 attributes
├── rfc5176.go          # RFC 5176 Dynamic Authorization attributes
├── rfc6929.go          # RFC 6929 extended attributes
├── parser/
│   └── parser.go       # pure-data parser, no runtime deps
└── gen/
    └── gen.go          # Go source generator
cmd/
└── dict-gen/
    └── main.go         # cobra CLI front-end
```

## 4. Parser

### 4.1 FreeRADIUS Dictionary Format

The parser handles the following directives:

| Directive         | Meaning                                        |
|-------------------|------------------------------------------------|
| `ATTRIBUTE name num type [opts]` | Wire attribute definition       |
| `VALUE attr name value`          | Enumerated value for an attribute |
| `VENDOR name id`                | SMI Private Enterprise Code       |
| `BEGIN-VENDOR name` / `END-VENDOR name` | Vendor sub-attribute scope |
| `ALIAS old new`                 | Attribute alias                   |
| `BEGIN-TLV name` / `END-TLV`    | TLV sub-attribute scope           |
| `BEGIN-ENUM name` / `END-ENUM`  | Enumerated value scope            |
| `$INCLUDE path`                 | Include another dictionary file   |

Lines beginning with `#` are comments. `#` inside a quoted value is
preserved. Unknown directives are skipped with a debug log.

### 4.2 Parsing API

```go
func Parse(r io.Reader) (*Dict, error)
func ParseFile(path string) (*Dict, error)
func ParseFiles(paths ...string) (*Dict, error)
```

`Parse` is the core; `ParseFile` and `ParseFiles` add file-path
awareness for `$INCLUDE` resolution. `$INCLUDE` paths are resolved
relative to the including file's directory, and a cycle-detection
`visited` set prevents infinite include loops.

### 4.3 Output Structure

```go
type Dict struct {
    Attributes []Attr
    Values     []Val
    Vendors    []Vendor
}

type Attr struct {
    Name       string
    Number     int
    Type       string  // raw FreeRADIUS type token
    Vendor     string  // empty if not a VSA
    Flags      AttrFlags
}

type Val struct {
    AttrName string
    Name     string
    Value    string
}

type Vendor struct {
    Name string
    ID   uint32
}
```

The parser is **pure data** — it does not import `packet/`, `types/`, or
any runtime RADIUS types. This keeps the parser trivially testable and
free of dependency cycles.

### 4.4 Unknown Value Types

FreeRADIUS defines many value types (`ifid`, `ipv6prefix`, `tlvs`,
`byte`, `short`, `signed`, `date`, `abinary`, ...) that this library
does not implement runtime codecs for. The parser preserves the raw
type string in `Attr.Type` and `RegisterFromDict` maps these to
`TypeRaw`, which is treated as opaque bytes by `packet.NewByName` and
`Attribute.Decode`.

## 5. Runtime Registration

```go
func (*Dictionary) RegisterFromDict(d *parser.Dict) error
```

Maps each `parser.Attr` into a `DictionaryAttr` entry keyed by number,
and each `parser.Attr.Name` into the name→number lookup table.
FreeRADIUS type strings are mapped to `ValueType` enum values:

| FreeRADIUS type | ValueType      |
|-----------------|----------------|
| `string`        | `TypeString`   |
| `integer`       | `TypeInteger`  |
| `ipaddr`        | `TypeIPAddr`   |
| `ipv6addr`      | `TypeIPv6Addr` |
| `octets`        | `TypeOctets`   |
| `raw` or `""`   | `TypeRaw`      |
| any other token | `TypeRaw`      |

## 6. Code Generator

### 6.1 Generator API

```go
func Gen(p *parser.Dict, w io.Writer, opt Options) error

type Options struct {
    Package string  // Go package name; required
    Header  string  // verbatim header written after the generated-by comment
}
```

The generator emits deterministic Go source sorted by `(Vendor, Name)`
for attributes and `(AttributeName, Name)` for values. The output
always begins with `// Code generated by dict-gen. DO NOT EDIT.` and
the package declaration.

### 6.2 Type Matrix

Each attribute emits a `const AttrXxx = N` declaration. The
accessor-pair type is chosen from the FreeRADIUS type:

| FreeRADIUS type | Setter signature                           | Getter signature                          |
|-----------------|--------------------------------------------|-------------------------------------------|
| `string`        | `AddXxx(p *packet.Packet, v string)`       | `GetXxx(p *packet.Packet) (string, bool)` |
| `integer`       | `AddXxx(p *packet.Packet, v uint32)`       | `GetXxx(p *packet.Packet) (uint32, bool)`  |
| `ipaddr`        | `AddXxx(p *packet.Packet, v net.IP)`       | `GetXxx(p *packet.Packet) (net.IP, bool)`  |
| `ipv6addr`      | `AddXxx(p *packet.Packet, v net.IP)`       | `GetXxx(p *packet.Packet) (net.IP, bool)`  |
| `octets`        | `AddXxx(p *packet.Packet, v []byte)`       | `GetXxx(p *packet.Packet) ([]byte, bool)` |
| `raw`           | `AddXxx(p *packet.Packet, v []byte)`       | `GetXxx(p *packet.Packet) ([]byte, bool)` |

VSA sub-attributes and extended-attribute sub-types emit only the
constant (no accessors) because the encoding path for VSAs goes
through `vendors.NewVSA` rather than `packet.NewString`/etc.

### 6.3 Identifier Sanitization

FreeRADIUS attribute names may contain hyphens (`MS-CHAP-Response`),
which are invalid in Go identifiers. The generator strips hyphens and
preserves case, so `MS-CHAP-Response` becomes `MSCHAPResponse`. Vendor
prefixes are joined with `_` (e.g. `AttrCisco_CiscoAVPair`).

### 6.4 CLI

```sh
dict-gen --in dictionary.freeradius --out attrs.go --pkg attrs [--header "//go:build attrs"]
```

The `--in` flag is repeatable; later files override earlier ones (same
semantics as FreeRADIUS's own include order). `--pkg` defaults to the
basename of `--out` without the extension.

## 7. Testing

- `parser/parser_test.go` — parser unit tests covering happy path,
  `$INCLUDE` (relative + absolute + cycle detection), unknown
  directives, quoted values with `#` inside, and value-type
  normalization.
- `dictionary/register_test.go` — runtime registration tests covering
  type-string→ValueType mapping and `TypeRaw` fallback.
- `gen/gen_test.go` — generator tests covering type matrix, identifier
  sanitization, deterministic ordering, and the constant-only path
  for VSAs.

Coverage: `dictionary/parser` 90.8 %, `dictionary/gen` 81.8 %,
`dictionary` (root) 86.7 %.

## 8. References

- FreeRADIUS dictionary format documentation:
  https://wiki.freeradius.org/concepts/Data_dictionary
- RFC 2865 §5.26 (Vendor-Specific)
- RFC 6929 §1.2 (Extended Attributes)
