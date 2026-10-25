package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestRenewalPolicyCannotAcquireRuntimeOrNetworkAuthority(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	allowed := map[string]bool{"bytes": true, "encoding/json": true, "errors": true, "io": true, "regexp": true, "strconv": true, "strings": true, "time": true, "unicode/utf8": true, "crypto/x509": true, "encoding/asn1": true, "encoding/base64": true, "crypto/rand": true, "math/big": true}
	exports := map[string]bool{"CertificateID": true, "ParseInformation": true, "NextCheck": true, "ErrorCheckAt": true, "FallbackWindow": true, "Select": true}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, item := range file.Imports {
			name, err := strconv.Unquote(item.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasPrefix(rel, "internal/renewalpolicy/") && !allowed[name] {
				t.Error("unreviewed renewal policy import", rel, name)
			}
			if name == "github.com/denyfirst/rootwell/internal/renewalpolicy" {
				t.Error("renewal policy wired before scoped custody review", rel)
			}
		}
		if strings.HasPrefix(rel, "internal/renewalpolicy/") {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.IsExported() && !exports[fn.Name.Name] {
					t.Error("unexpected policy capability", fn.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
