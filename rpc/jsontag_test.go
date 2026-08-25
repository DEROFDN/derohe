package rpc

// Struct-tag hygiene for the JSON-RPC surface.
//
// Every type in this package is part of derod's or the wallet's public wire
// format. A wrong `json:"..."` tag is invisible at compile time, invisible in
// unit tests that only exercise Go structs, and only shows up as a field a
// client can never read. This walks the package source and asserts the tags
// are sane.
//
// It parses the source rather than using reflection so it can see every type
// in the package without anyone remembering to add it to a list.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

// Tags that name a Go builtin type are almost always a mistake: the author
// typed the field's TYPE where its NAME belongs.
var builtinTypeNames = map[string]bool{
	"string": true, "bool": true, "byte": true, "rune": true, "error": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"float32": true, "float64": true, "interface{}": true,
}

type fieldTag struct {
	structName string
	fieldName  string
	tagName    string
	pos        string
}

// collectTags parses every non-test .go file in the package directory and
// returns the json tag of every field of every struct type it finds.
func collectTags(t *testing.T) []fieldTag {
	t.Helper()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing package: %v", err)
	}

	var out []fieldTag
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, f := range st.Fields.List {
					if f.Tag == nil {
						// Unexported or embedded fields legitimately have no tag;
						// exported ones are checked in TestExportedFieldsHaveJSONTags.
						continue
					}
					raw := strings.Trim(f.Tag.Value, "`")
					jsonTag := reflect.StructTag(raw).Get("json")
					if jsonTag == "" {
						continue
					}
					name := strings.Split(jsonTag, ",")[0]
					if name == "" || name == "-" {
						continue
					}
					for _, ident := range f.Names {
						out = append(out, fieldTag{
							structName: ts.Name.Name,
							fieldName:  ident.Name,
							tagName:    name,
							pos:        fset.Position(f.Pos()).String(),
						})
					}
				}
				return true
			})
		}
	}
	if len(out) == 0 {
		t.Fatal("collected zero json tags — the parser is not seeing the package, " +
			"so every test below would pass vacuously")
	}
	return out
}

// A json tag naming a Go builtin type is the signature of a typo where the
// field's type was written instead of its name.
//
// This is what caught SendRawTransaction_Result.Reason being tagged
// `json:"string"`.
func TestNoJSONTagNamedAfterAGoType(t *testing.T) {
	for _, ft := range collectTags(t) {
		if builtinTypeNames[ft.tagName] {
			t.Errorf("%s: %s.%s has json tag %q, which is a Go type name — "+
				"did you mean json:%q?",
				ft.pos, ft.structName, ft.fieldName, ft.tagName,
				strings.ToLower(ft.fieldName))
		}
	}
}

// Two fields sharing a json tag inside one struct means one of them silently
// never reaches the client, and which one wins depends on field order.
func TestNoDuplicateJSONTagsWithinAStruct(t *testing.T) {
	seen := map[string]fieldTag{}
	for _, ft := range collectTags(t) {
		key := ft.structName + "\x00" + ft.tagName
		if prev, dup := seen[key]; dup {
			t.Errorf("%s: %s has two fields tagged %q (%s and %s) — one of them "+
				"never reaches the wire",
				ft.pos, ft.structName, ft.tagName, prev.fieldName, ft.fieldName)
			continue
		}
		seen[key] = ft
	}
}

// The wire format is lowercase throughout. A stray uppercase tag is a
// client-visible inconsistency that is painful to change later.
func TestJSONTagsAreLowercase(t *testing.T) {
	for _, ft := range collectTags(t) {
		if ft.tagName != strings.ToLower(ft.tagName) {
			t.Errorf("%s: %s.%s has json tag %q; this package's wire format is "+
				"lowercase",
				ft.pos, ft.structName, ft.fieldName, ft.tagName)
		}
	}
}
