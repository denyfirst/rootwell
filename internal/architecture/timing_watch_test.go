package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTimingWatchCannotAcquireOrderDNSOrIndependentUnlock(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	allowed := map[string]bool{"Revision": true, "ReadTimingReadiness": true, "RunStagingRenewalTiming": true, "Authenticate": true}
	for _, path := range []string{"cmd/rootwelld/timing_watch.go", "cmd/rootwelld/timing_watch_api.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "instanceaccess" && !allowed[sel.Sel.Name] {
							t.Error("unreviewed watch custody", path, sel.Sel.Name)
						}
						if ident.Name == "acmestaging" && sel.Sel.Name != "RenewalInformation" {
							t.Error("unreviewed watch network capability", path, sel.Sel.Name)
						}
					}
				}
			}
			if spec, ok := n.(*ast.TypeSpec); ok && spec.Name.Name == "timingWatch" {
				if st, ok := spec.Type.(*ast.StructType); ok {
					for _, f := range st.Fields.List {
						if ident, ok := f.Type.(*ast.Ident); ok && ident.Name == "session" {
							t.Error("watch retains session unlock")
						}
					}
				}
			}
			return true
		})
	}
}
