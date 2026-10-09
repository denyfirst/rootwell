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

func TestWorkbenchHasNoNetworkOrProcessImports(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate architecture test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}

			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range file.Imports {
				importPath, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return err
				}
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					relative = path
				}
				allowedProbe := filepath.ToSlash(relative) == "cmd/rootwell-probe/main.go" &&
					(importPath == "net" || strings.HasPrefix(importPath, "net/"))
				allowedLoopbackServer := (filepath.ToSlash(relative) == "cmd/rootwelld/main.go" &&
					(importPath == "net" || importPath == "net/http")) ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/gate.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/inventory_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/certificate_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/acme_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/acme_directory_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/acme_account_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/acme_registration_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/inventory_lifecycle.go" && importPath == "net/http")
				// netip only parses immutable address values; it has no DNS/socket API.
				allowedAddressParser := filepath.ToSlash(relative) == "internal/csrworkbench/request.go" && importPath == "net/netip"
				allowedDirectoryConnector := (filepath.ToSlash(relative) == "internal/acmestaging/directory.go" || filepath.ToSlash(relative) == "internal/acmestaging/registration.go") &&
					(importPath == "net" || importPath == "net/http" || importPath == "net/netip" || importPath == "net/url")
				if forbiddenImport(importPath) && !allowedProbe && !allowedLoopbackServer && !allowedAddressParser && !allowedDirectoryConnector {
					t.Errorf("forbidden Workbench import %q in %s", importPath, relative)
				}
				if importPath == "github.com/denyfirst/rootwell/internal/acmestaging" && filepath.ToSlash(relative) != "cmd/rootwelld/acme_directory_api.go" && filepath.ToSlash(relative) != "cmd/rootwelld/acme_registration_api.go" ||
					importPath == "golang.org/x/crypto/acme" && filepath.ToSlash(relative) != "internal/acmestaging/directory.go" && filepath.ToSlash(relative) != "internal/acmestaging/registration.go" {
					t.Errorf("ACME network authority outside reviewed directory connector: %s", relative)
				}
				if importPath == "github.com/denyfirst/rootwell/internal/instanceaccess" &&
					!strings.HasPrefix(filepath.ToSlash(relative), "cmd/rootwelld/") {
					t.Errorf("installation access must remain outside the offline Workbench: %s", relative)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", directory, err)
		}
	}
}

// Local key preparation remains covered separately. Only this new route gains
// the reviewed staging terms/register/find capability, never orders or URLs.
func TestStagingRegistrationHasOnlyReviewedAccountClientMethods(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	for path, methods := range map[string]map[string]bool{
		"internal/acmestaging/directory.go":    {"Discover": true},
		"internal/acmestaging/registration.go": {"Discover": true, "Register": true, "GetReg": true},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := selector.X.(*ast.Ident)
			if ok && id.Name == "client" && !methods[selector.Sel.Name] {
				t.Errorf("unreviewed account client operation: %s in %s", selector.Sel.Name, path)
			}
			return true
		})
	}
}

func forbiddenImport(path string) bool {
	return path == "net" || strings.HasPrefix(path, "net/") || path == "os/exec" || path == "plugin" || path == "unsafe" ||
		path == "golang.org/x/crypto/openpgp" || strings.HasPrefix(path, "golang.org/x/crypto/openpgp/")
}

// This regression guard is not a sandbox: new ACME capabilities need an
// explicit boundary review, not an accidental client/storage import.
func TestACMESetupHasNoOutboundOrPersistenceImports(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	for path, allowed := range map[string]map[string]bool{
		"internal/acmeplan/plan.go": {"errors": true, "strings": true, "github.com/denyfirst/rootwell/internal/csrworkbench": true},
		"cmd/rootwelld/acme_api.go": {"bytes": true, "encoding/json": true, "io": true, "mime": true, "net/http": true, "unicode/utf8": true, "github.com/denyfirst/rootwell/internal/acmeplan": true},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil || !allowed[value] || imported.Name != nil {
				t.Errorf("unreviewed ACME setup import in %s: %s", path, imported.Path.Value)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			selector, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if id.Name == "http" && !strings.HasPrefix(selector.Sel.Name, "Status") &&
				selector.Sel.Name != "Error" && selector.Sel.Name != "MaxBytesReader" &&
				selector.Sel.Name != "Request" && selector.Sel.Name != "ResponseWriter" && selector.Sel.Name != "MethodPost" {
				t.Errorf("outbound-capable http selector in %s: %s", path, selector.Sel.Name)
			}
			if id.Name == "csrworkbench" && selector.Sel.Name != "NormalizeDNSNames" {
				t.Errorf("key/CSR capability in setup: %s", selector.Sel.Name)
			}
			return true
		})
	}
}

func TestACMEAccountPreparationHasNoOutboundHTTPAuthority(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "cmd/rootwelld/acme_account_api.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"bytes": true, "encoding/json": true, "errors": true, "io": true, "mime": true, "net/http": true, "runtime": true, "unicode/utf8": true,
		"github.com/denyfirst/rootwell/internal/acmeplan": true, "github.com/denyfirst/rootwell/internal/instanceaccess": true, "github.com/denyfirst/rootwell/internal/inventorystore": true}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || !allowed[path] || imported.Name != nil {
			t.Errorf("unreviewed account-preparation import: %s", imported.Path.Value)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		s, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := s.X.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "http" && !strings.HasPrefix(s.Sel.Name, "Status") && s.Sel.Name != "Request" && s.Sel.Name != "ResponseWriter" &&
			s.Sel.Name != "Error" && s.Sel.Name != "MaxBytesReader" && s.Sel.Name != "MethodPost" {
			t.Errorf("outbound HTTP authority in local preparation: %s", s.Sel.Name)
		}
		if id.Name == "acmeplan" && s.Sel.Name != "Provider" {
			t.Errorf("unreviewed account provider capability: %s", s.Sel.Name)
		}
		return true
	})
}
