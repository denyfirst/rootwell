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

func TestFixedACMEProfilesCannotBecomeRuntimePromotionOrTrustConfiguration(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	profile := "internal/acmeprofile/profile.go"
	production := "internal/acmecertificate/production.go"
	productionImports := map[string]bool{"bytes": true, "crypto/sha256": true, "crypto/x509": true, "embed": true, "encoding/hex": true, "errors": true, "strings": true, "time": true, "github.com/denyfirst/rootwell/internal/certverify": true}
	exports := map[string]bool{"Parse": true, "Valid": true, "Provider": true, "Host": true, "Origin": true, "Directory": true, "Namespace": true, "TestOnly": true, "AccountURL": true, "OrderURL": true, "ResourceURL": true}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
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
		for _, imp := range file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if rel == profile && p != "errors" && p != "strings" {
				t.Error("profile catalog acquired capability", p)
			}
			if rel == production && !productionImports[p] {
				t.Error("production trust acquired ambient capability", p)
			}
			if p == "github.com/denyfirst/rootwell/internal/acmeprofile" && rel != "internal/acmeorder/model.go" {
				t.Error("unreviewed profile consumer", rel)
			}
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.IsExported() {
				if rel == profile && !exports[fn.Name.Name] {
					t.Error("unreviewed profile authority", fn.Name.Name)
				}
				if rel == production && fn.Name.Name != "CheckProduction" {
					t.Error("production trust gained another public entry", fn.Name.Name)
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				switch id.Name {
				case "CheckProduction", "productionReceipt", "productionTrust", "checkedProductionRoots", "productionRootPEM", "productionRootPins":
					if rel != production {
						t.Error("production trust wired before scoped custody review", rel, id.Name)
					}
				}
			}
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "acmeprofile" {
					if rel != "internal/acmeorder/model.go" || !map[string]bool{"Staging": true, "AccountURL": true, "OrderURL": true, "ResourceURL": true}[sel.Sel.Name] {
						t.Error("legacy route can select a production profile", rel, sel.Sel.Name)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
