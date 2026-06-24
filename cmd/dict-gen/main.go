// Command dict-gen reads one or more FreeRADIUS dictionary files and
// emits a Go source file with typed constants and accessor functions.
//
// Usage:
//
//	dict-gen -in dictionary.rfc2865 -in dictionary.rfc2866 \
//	         -out attrs/attrs.go -pkg attrs
//
// The output is deterministic: running the tool twice on the same input
// produces byte-identical output, so it is safe to commit generated files
// and re-run dict-gen in CI to verify they have not drifted.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wxccs/radius/dictionary/gen"
	"github.com/wxccs/radius/dictionary/parser"
)

func main() {
	if err := newCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "dict-gen:", err)
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	var (
		inputs []string
		out    string
		pkg    string
		header string
	)
	cmd := &cobra.Command{
		Use:   "dict-gen",
		Short: "Generate Go source from FreeRADIUS dictionaries",
		Long: "Reads one or more FreeRADIUS dictionary files and emits a " +
			"Go source file with typed constants and accessor functions " +
			"for every attribute and enumerated value.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(inputs) == 0 {
				return fmt.Errorf("at least one -in dictionary file is required")
			}
			if out == "" {
				return fmt.Errorf("-out output path is required")
			}
			if pkg == "" {
				// Default to the directory name of -out.
				parts := strings.Split(strings.TrimRight(out, "/"), "/")
				last := parts[len(parts)-1]
				if dot := strings.IndexByte(last, '.'); dot > 0 {
					pkg = last[:dot]
				} else {
					pkg = last
				}
				pkg = sanitizePkgName(pkg)
			}

			d, err := parser.ParseFiles(inputs...)
			if err != nil {
				return fmt.Errorf("parse: %w", err)
			}

			f, err := os.Create(out)
			if err != nil {
				return fmt.Errorf("open output: %w", err)
			}
			defer f.Close()

			opt := gen.Options{Package: pkg, Header: header}
			if err := gen.Gen(d, f, opt); err != nil {
				return fmt.Errorf("generate: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&inputs, "in", nil,
		"input dictionary file (repeatable; later files override earlier)")
	cmd.Flags().StringVar(&out, "out", "",
		"output Go source file path (required)")
	cmd.Flags().StringVar(&pkg, "pkg", "",
		"Go package name in the output file (defaults to the -out basename without extension)")
	cmd.Flags().StringVar(&header, "header", "",
		"verbatim header written after the generated-by comment (e.g. //go:build attrs)")
	return cmd
}

// sanitizePkgName converts a directory/file basename into a valid Go
// identifier. Non-identifier characters are replaced with underscores
// and a leading digit gets an underscore prefix.
func sanitizePkgName(s string) string {
	if s == "" {
		return "attrs"
	}
	out := make([]rune, 0, len(s))
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = append([]rune{'_'}, out...)
	}
	return string(out)
}
