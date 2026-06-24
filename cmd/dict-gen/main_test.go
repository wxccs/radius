package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLI_GeneratesValidSource runs the dict-gen binary against a small
// FreeRADIUS dictionary and verifies the emitted source is syntactically
// valid Go and contains the expected symbols.
//
// The test invokes `go run ./cmd/dict-gen` (the package under test), so
// the Go toolchain must be on PATH. It writes the generated source to a
// temp directory and parses it with go/parser to validate syntax; it
// does not attempt to compile the output, since that would require the
// generated file to live inside the module and import the runtime
// packet package — which is already exercised by the gen package tests.
func TestCLI_GeneratesValidSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI end-to-end test in short mode")
	}

	tmpRoot := t.TempDir()
	pkgDir := filepath.Join(tmpRoot, "genattrs")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))

	dictPath := filepath.Join(tmpRoot, "test.dict")
	require.NoError(t, os.WriteFile(dictPath, []byte(`# generated for test
ATTRIBUTE User-Name 1 string
ATTRIBUTE NAS-Port 5 integer
ATTRIBUTE NAS-IP-Address 4 ipaddr
ATTRIBUTE NAS-IPv6-Address 95 ipv6addr
ATTRIBUTE State 24 octets
ATTRIBUTE TLS-Session-Info 145 ifid
ATTRIBUTE Vendor-Specific 26 vsa

VALUE Service-Type Login-User 1
VALUE Service-Type Framed-User 2
`), 0o644))

	outPath := filepath.Join(pkgDir, "attrs.go")
	cmd := exec.Command("go", "run", "./cmd/dict-gen",
		"--in", dictPath,
		"--out", outPath,
		"--pkg", "genattrs",
	)
	cmd.Dir = projectRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "dict-gen failed: %s", out)

	src, err := os.ReadFile(outPath)
	require.NoError(t, err)

	// 1) Syntactically valid Go source.
	fset := token.NewFileSet()
	_, err = parser.ParseFile(fset, "attrs.go", src, parser.AllErrors)
	require.NoErrorf(t, err, "generated source is not valid Go:\n%s", src)

	// 2) Contains the expected package clause and symbols.
	assert.Contains(t, string(src), "package genattrs")
	assert.Contains(t, string(src), "AttrUserName = 1")
	assert.Contains(t, string(src), "AttrNASPort = 5")
	assert.Contains(t, string(src), "AttrVendorSpecific = 26")
	assert.Contains(t, string(src), "ValServiceTypeLoginUser = 1")
	assert.Contains(t, string(src), "ValServiceTypeFramedUser = 2")
	assert.Contains(t, string(src), "func AddUserName(p *packet.Packet, v string) {")
	assert.Contains(t, string(src), "func GetUserName(p *packet.Packet) (string, bool) {")
	assert.Contains(t, string(src), "func AddNASIPAddress(p *packet.Packet, v net.IP) {")

	// 3) The vsa attribute gets a constant but no typed accessor.
	assert.Contains(t, string(src), "no typed accessor is generated")
	assert.NotContains(t, string(src), "func AddVendorSpecific(")
}

func TestCLI_DefaultPackageName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI end-to-end test in short mode")
	}

	tmpRoot := t.TempDir()
	dictPath := filepath.Join(tmpRoot, "test.dict")
	require.NoError(t, os.WriteFile(dictPath, []byte("ATTRIBUTE Foo 1 string\n"), 0o644))

	// No -pkg flag: the package name is derived from -out basename.
	outPath := filepath.Join(tmpRoot, "myattrs.go")
	cmd := exec.Command("go", "run", "./cmd/dict-gen",
		"--in", dictPath,
		"--out", outPath,
	)
	cmd.Dir = projectRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "dict-gen failed: %s", out)

	src, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(src), "package myattrs")
}

func TestCLI_MissingInErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI end-to-end test in short mode")
	}

	cmd := exec.Command("go", "run", "./cmd/dict-gen", "--out", "/tmp/x.go")
	cmd.Dir = projectRoot(t)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "dict-gen must error when -in is missing")
	assert.Contains(t, string(out), "at least one -in")
}

func TestCLI_MissingOutErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI end-to-end test in short mode")
	}

	tmpRoot := t.TempDir()
	dictPath := filepath.Join(tmpRoot, "test.dict")
	require.NoError(t, os.WriteFile(dictPath, []byte("ATTRIBUTE Foo 1 string\n"), 0o644))

	cmd := exec.Command("go", "run", "./cmd/dict-gen", "--in", dictPath)
	cmd.Dir = projectRoot(t)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "dict-gen must error when -out is missing")
	assert.Contains(t, string(out), "-out")
}

// projectRoot returns the module root by walking up from the test file
// location. The test file lives in cmd/dict-gen/, so the module root
// is two levels up.
func projectRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Dir(filepath.Dir(wd))
	require.FileExists(t, filepath.Join(root, "go.mod"),
		"could not locate module root from %s", wd)
	return root
}
