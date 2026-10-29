package architecture

import (
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenewalJobOnlyBorrowedSessionAndLockedTransactions(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	worker, api, operations := "cmd/rootwelld/renewal_job.go", "cmd/rootwelld/renewal_job_api.go", "cmd/rootwelld/renewal_job_operations.go"
	allowed := map[string]map[string]bool{
		worker:     {"Revision": true, "ReadRenewalCycle": true},
		api:        {"ReadRenewalCycle": true, "Authenticate": true, "ErrWrongPassword": true},
		operations: {"RunStagingRenewalTiming": true, "CloseStagingRequest": true, "RunStagingRenewalOrder": true, "RunStagingOrder": true, "PrepareStagingDNSPlan": true, "RunStagingDNS": true, "AcknowledgeStagingDNS": true, "RunStagingValidation": true, "PrepareStagingCertificateRequest": true, "RunStagingCertificate": true},
	}
	guarded := map[string]map[string]bool{
		"newRenewalJob": {worker: true, api: true}, "executeRenewalAction": {worker: true, operations: true},
		"ReadRenewalCycle":   {"internal/inventorystore/renewal_cycle.go": true, "internal/instanceaccess/renewal_cycle_linux.go": true, "internal/instanceaccess/renewal_cycle_other.go": true, worker: true, api: true},
		"readRenewalCycleAt": {"internal/inventorystore/renewal_cycle.go": true},
		"DecideRenewalCycle": {"internal/inventorystore/renewal_cycle.go": true, worker: true, api: true},
	}
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
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if paths, guard := guarded[id.Name]; guard && !paths[rel] {
					t.Error("unreviewed renewal authority", rel, id.Name)
				}
			}
			if allowed[rel] != nil {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok {
						if pkg.Name == "instanceaccess" && !allowed[rel][sel.Sel.Name] {
							t.Error("renewal bypasses reviewed transaction", rel, sel.Sel.Name)
						}
						if pkg.Name == "acmestaging" && !map[string]bool{"RenewalInformation": true, "DNSOrder": true, "DNSValidation": true, "Certificate": true, "CloudflareTXT": true, "CertificateObservation": true}[sel.Sel.Name] {
							t.Error("renewal acquired unreviewed transport", sel.Sel.Name)
						}
					}
				}
			}
			if spec, ok := n.(*ast.TypeSpec); ok && spec.Name.Name == "renewalJob" {
				st, ok := spec.Type.(*ast.StructType)
				if !ok {
					t.Fatal("job no longer a public-scope struct")
				}
				for _, field := range st.Fields.List {
					var out strings.Builder
					if err := format.Node(&out, token.NewFileSet(), field.Type); err != nil {
						t.Fatal(err)
					}
					typ := out.String()
					if !map[string]bool{"[32]byte": true, "string": true, "[]string": true, "uint64": true, "int": true, "time.Time": true, "context.Context": true, "context.CancelFunc": true, "chan struct{}": true}[typ] {
						t.Error("retained independent authority", typ)
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
