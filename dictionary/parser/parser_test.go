package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_BasicAttribute(t *testing.T) {
	src := `# minimal sample
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string encrypt=1
ATTRIBUTE NAS-IP-Address 4 ipaddr
ATTRIBUTE Service-Type 6 integer
ATTRIBUTE CHAP-Challenge 60 octets has_tag
`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, d.Attributes, 5)

	assert.Equal(t, Attr{Name: "User-Name", Type: 1, ValueType: "string"}, d.Attributes[0])
	assert.Equal(t, Attr{Name: "User-Password", Type: 2, ValueType: "string", Encrypt: 1}, d.Attributes[1])
	assert.Equal(t, Attr{Name: "NAS-IP-Address", Type: 4, ValueType: "ipaddr"}, d.Attributes[2])
	assert.Equal(t, Attr{Name: "Service-Type", Type: 6, ValueType: "integer"}, d.Attributes[3])
	assert.Equal(t, Attr{Name: "CHAP-Challenge", Type: 60, ValueType: "octets", HasTag: true}, d.Attributes[4])
}

func TestParse_UnknownTypeBecomesRaw(t *testing.T) {
	// ifid, ipv6prefix, byte, short, signed, date, tlvs are not modeled
	// by our runtime codec; the parser normalizes them to "raw".
	src := `ATTRIBUTE TLS-Session-Info 145 tlvs
ATTRIBUTE Chargeable-User-Identity 89 ifid
ATTRIBUTE Framed-IPv6-Prefix 97 ipv6prefix
ATTRIBUTE Some-Short 200 byte
ATTRIBUTE Some-Date 201 date
`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	for _, a := range d.Attributes {
		assert.Equal(t, "raw", a.ValueType, "attribute %s must be raw", a.Name)
	}
}

func TestParse_ValueEntries(t *testing.T) {
	src := `VALUE Service-Type Login-User 1
VALUE Service-Type Framed-User 2
VALUE Framed-Protocol PPP 1`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, d.Values, 3)
	assert.Equal(t, Val{AttributeName: "Service-Type", Name: "Login-User", Number: 1}, d.Values[0])
	assert.Equal(t, Val{AttributeName: "Service-Type", Name: "Framed-User", Number: 2}, d.Values[1])
	assert.Equal(t, Val{AttributeName: "Framed-Protocol", Name: "PPP", Number: 1}, d.Values[2])
}

func TestParse_VendorAndNestedVSA(t *testing.T) {
	src := `VENDOR Microsoft 311
BEGIN-VENDOR Microsoft
ATTRIBUTE MS-CHAP-Response 1 octets
ATTRIBUTE MS-MPPE-Send-Key 16 octets
END-VENDOR
ATTRIBUTE Vendor-Specific 26 vsa
`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, d.Vendors, 1)
	assert.Equal(t, Vendor{Name: "Microsoft", ID: 311}, d.Vendors[0])
	require.Len(t, d.Attributes, 3)
	assert.Equal(t, "Microsoft", d.Attributes[0].Vendor)
	assert.Equal(t, "Microsoft", d.Attributes[1].Vendor)
	assert.Empty(t, d.Attributes[2].Vendor, "post-END-VENDOR attrs must not carry vendor")
}

func TestParse_CommentsAndQuotes(t *testing.T) {
	// '#' beginning a word is a comment; '#' inside a quoted token is
	// preserved. Empty lines and standalone comments are ignored.
	src := `# top-level comment

ATTRIBUTE Foo-#-Bar 1 string # trailing comment
ATTRIBUTE Baz 2 string
`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, d.Attributes, 2)
	assert.Equal(t, "Foo-#-Bar", d.Attributes[0].Name)
	assert.Equal(t, "Baz", d.Attributes[1].Name)
}

func TestParse_HexAttributeNumber(t *testing.T) {
	src := `ATTRIBUTE Foo 0xff string
ATTRIBUTE Bar 0o17 string
ATTRIBUTE Baz 0b1 string
`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, d.Attributes, 3)
	assert.Equal(t, byte(0xff), d.Attributes[0].Type)
	assert.Equal(t, byte(0o17), d.Attributes[1].Type)
	assert.Equal(t, byte(1), d.Attributes[2].Type)
}

func TestParse_UnknownDirectiveIgnored(t *testing.T) {
	// FreeRADIUS adds new directives periodically. Unknown ones must
	// be tolerated so a dictionary file with future tokens still loads.
	src := `BEGIN-ENUM foo
ATTRIBUTE SomeAttr 1 string
SOME-NEW-FUTURE-DIRECTIVE bar baz
END-ENUM
`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, d.Attributes, 1)
}

func TestParse_AlIgnored(t *testing.T) {
	src := `ATTRIBUTE Foo 1 string
ALIAS Foo Foo-Alias
`
	d, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, d.Attributes, 1)
}

func TestParse_Errors(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"too few fields", "ATTRIBUTE User-Name 1"},
		{"bad number", "ATTRIBUTE User-Name notanumber string"},
		{"number out of range", "ATTRIBUTE User-Name 256 string"},
		{"bad encrypt flag", "ATTRIBUTE User-Password 2 string encrypt=notanumber"},
		{"bad value number", "VALUE Foo Bar notanumber"},
		{"vendor missing id", "VENDOR Microsoft"},
		{"vendor bad id", "VENDOR Microsoft notanumber"},
		{"begin-vendor missing name", "BEGIN-VENDOR"},
		{"include wrong arg count", "$INCLUDE a b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(c.src))
			assert.Error(t, err, "expected error for %q", c.src)
		})
	}
}

func TestParse_FromReaderIncludesRejected(t *testing.T) {
	// Parse(io.Reader) has no base directory, so $INCLUDE must fail
	// rather than guessing a relative path.
	_, err := Parse(strings.NewReader("$INCLUDE other.dict"))
	require.Error(t, err)
}

func TestParseFile_ResolvesInclude(t *testing.T) {
	dir := t.TempDir()
	// Sub-file declares an attribute; main file includes it.
	subPath := filepath.Join(dir, "sub.dict")
	require.NoError(t, os.WriteFile(subPath, []byte("ATTRIBUTE From-Sub 1 string\n"), 0o644))
	mainPath := filepath.Join(dir, "main.dict")
	mainSrc := "ATTRIBUTE From-Main 2 string\n$INCLUDE sub.dict\n"
	require.NoError(t, os.WriteFile(mainPath, []byte(mainSrc), 0o644))

	d, err := ParseFile(mainPath)
	require.NoError(t, err)
	require.Len(t, d.Attributes, 2)
	assert.Equal(t, "From-Main", d.Attributes[0].Name)
	assert.Equal(t, "From-Sub", d.Attributes[1].Name)
}

func TestParseFile_RelativeInclude(t *testing.T) {
	// $INCLUDE with a relative path is resolved against the current
	// file's directory, not the process CWD.
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	require.NoError(t, os.Mkdir(nested, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "leaf.dict"),
		[]byte("ATTRIBUTE Leaf 1 string\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.dict"),
		[]byte("$INCLUDE nested/leaf.dict\n"), 0o644))

	d, err := ParseFile(filepath.Join(dir, "root.dict"))
	require.NoError(t, err)
	require.Len(t, d.Attributes, 1)
	assert.Equal(t, "Leaf", d.Attributes[0].Name)
}

func TestParseFile_CycleDetected(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.dict")
	b := filepath.Join(dir, "b.dict")
	require.NoError(t, os.WriteFile(a, []byte("$INCLUDE b.dict\n"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("$INCLUDE a.dict\n"), 0o644))

	_, err := ParseFile(a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circular")
}

func TestParseFiles_Merges(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "p1.dict")
	p2 := filepath.Join(dir, "p2.dict")
	require.NoError(t, os.WriteFile(p1, []byte("ATTRIBUTE A 1 string\n"), 0o644))
	require.NoError(t, os.WriteFile(p2, []byte("ATTRIBUTE B 2 integer\nVENDOR V 1\n"), 0o644))

	d, err := ParseFiles(p1, p2)
	require.NoError(t, err)
	require.Len(t, d.Attributes, 2)
	require.Len(t, d.Vendors, 1)
}
