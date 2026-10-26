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
	policyConsumers := map[string]bool{"internal/acmestaging/renewal_info.go": true, "internal/inventorystore/renewal_timing.go": true, "internal/inventorystore/renewal_timing_operation.go": true, "internal/renewalrecord/record.go": true}
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
			if name == "github.com/denyfirst/rootwell/internal/renewalpolicy" && !policyConsumers[rel] {
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
		if rel == "internal/acmestaging/renewal_info.go" {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.IsExported() && fn.Name.Name != "RenewalInformation" && (fn.Recv == nil || fn.Name.Name != "Error") {
					t.Error("ARI protocol exported before custody review", fn.Name.Name)
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				switch ident.Name {
				case "renewalInformation", "renewalReceipt", "ariObservation", "ariFailure", "ariSession", "validARIURL", "renewalInfoURL":
					if rel != "internal/acmestaging/renewal_info.go" {
						t.Error("unreviewed ARI protocol consumer", rel, ident.Name)
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

func TestRenewalTimingHasOnlyLockedInternalConsumers(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	model := "internal/inventorystore/renewal_timing.go"
	operation := "internal/inventorystore/renewal_timing_operation.go"
	wait := "internal/inventorystore/renewal_wait.go"
	linux := "internal/instanceaccess/renewal_timing_linux.go"
	other := "internal/instanceaccess/renewal_timing_other.go"
	api := "cmd/rootwelld/renewal_timing_api.go"
	watch := "cmd/rootwelld/timing_watch.go"
	allowed := map[string]map[string]bool{
		"ReadStagingRenewalTiming":      {model: true, linux: true, other: true, api: true},
		"BeginStagingRenewalTiming":     {operation: true, linux: true},
		"ExecuteStagingRenewalTiming":   {operation: true, linux: true},
		"InterruptStagingRenewalTiming": {operation: true, linux: true, other: true, api: true},
		"RunStagingRenewalTiming":       {linux: true, other: true, api: true, watch: true},
		"ReadStagingProviderWait":       {wait: true, "internal/instanceaccess/provider_wait_linux.go": true},
		"RenewalInformation":            {"internal/acmestaging/renewal_info.go": true, api: true, watch: true},
		"timingConnect":                 {"cmd/rootwelld/gate.go": true, api: true, watch: true},
		"newTimingWatch":                {watch: true, "cmd/rootwelld/timing_watch_api.go": true},
		"ReadTimingReadiness":           {"internal/inventorystore/timing_watch.go": true, "internal/instanceaccess/timing_watch_linux.go": true, "internal/instanceaccess/timing_watch_other.go": true, "cmd/rootwelld/timing_watch_api.go": true, watch: true},
		"RunStagingProviderRead":        {"internal/instanceaccess/provider_wait_linux.go": true, "internal/instanceaccess/provider_wait_other.go": true, "cmd/rootwelld/acme_directory_api.go": true, "cmd/rootwelld/acme_registration_api.go": true},
		"stagingProviderPermit":         {"internal/instanceaccess/provider_wait_linux.go": true, "internal/instanceaccess/acme_registration_linux.go": true, "internal/instanceaccess/acme_order_linux.go": true, "internal/instanceaccess/acme_validation_linux.go": true, "internal/instanceaccess/acme_certificate_linux.go": true},
		"beginTimingAt":                 {operation: true}, "executeTimingAt": {operation: true}, "interruptTimingAt": {operation: true},
		"readTimingStatusAt": {model: true, operation: true, "internal/inventorystore/timing_watch.go": true}, "readStagingWaitAt": {wait: true},
	}
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
			if name == "github.com/denyfirst/rootwell/internal/renewalrecord" && rel != model && rel != operation && rel != api && rel != watch && rel != "internal/acmestaging/renewal_info.go" {
				t.Error("unreviewed timing receipt consumer", rel)
			}
			if rel == "internal/renewalrecord/record.go" && name != "github.com/denyfirst/rootwell/internal/providerretry" && name != "github.com/denyfirst/rootwell/internal/renewalpolicy" {
				t.Error("receipt acquired authority", name)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				if paths, guarded := allowed[ident.Name]; guarded && !paths[rel] {
					t.Error("unreviewed renewal timing authority", rel, ident.Name)
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

// Complement executable Linux refusal tests: deleting a barrier must fail even
// on a native development host that cannot execute Linux custody.
func TestStagingProviderBarrierPresentInEveryNetworkWriter(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	for _, path := range []string{"internal/instanceaccess/acme_registration_linux.go", "internal/instanceaccess/acme_order_linux.go", "internal/instanceaccess/acme_validation_linux.go", "internal/instanceaccess/acme_certificate_linux.go", "cmd/rootwelld/acme_directory_api.go", "cmd/rootwelld/acme_registration_api.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		want := "stagingProviderPermit"
		if strings.HasPrefix(path, "cmd/") {
			want = "RunStagingProviderRead"
		}
		found := false
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					found = found || fn.Name == want
				case *ast.SelectorExpr:
					found = found || fn.Sel.Name == want
				}
			}
			return true
		})
		if !found {
			t.Error("missing all-CA provider barrier", path)
		}
	}
}
