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
					(filepath.ToSlash(relative) == "cmd/rootwelld/cloudflare_config_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/dns_operation_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/automation_status_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/renewal_timing_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/timing_watch_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/provider_wait.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/acme_registration_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/acme_order_api.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/acme_renewal_navigation.go" && importPath == "net/http") ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/inventory_lifecycle.go" && importPath == "net/http")
				// netip only parses immutable address values; it has no DNS/socket API.
				allowedAddressParser := filepath.ToSlash(relative) == "internal/csrworkbench/request.go" && importPath == "net/netip"
				allowedDirectoryConnector := (filepath.ToSlash(relative) == "internal/acmestaging/directory.go" || filepath.ToSlash(relative) == "internal/acmestaging/registration.go" || filepath.ToSlash(relative) == "internal/acmestaging/order.go" || filepath.ToSlash(relative) == "internal/acmestaging/validation.go" || filepath.ToSlash(relative) == "internal/acmestaging/certificate.go") &&
					(importPath == "net" || importPath == "net/http" || importPath == "net/netip" || importPath == "net/url")
				allowedDNSCore := filepath.ToSlash(relative) == "internal/acmestaging/cloudflare.go" && (importPath == "net/http" || importPath == "net/url")
				allowedARIRead := filepath.ToSlash(relative) == "internal/acmestaging/renewal_info.go" && (importPath == "net/http" || importPath == "net")
				if forbiddenImport(importPath) && !allowedProbe && !allowedLoopbackServer && !allowedAddressParser && !allowedDirectoryConnector && !allowedDNSCore && !allowedARIRead {
					t.Errorf("forbidden Workbench import %q in %s", importPath, relative)
				}
				if importPath == "github.com/denyfirst/rootwell/internal/acmestaging" && filepath.ToSlash(relative) != "cmd/rootwelld/timing_watch.go" && filepath.ToSlash(relative) != "cmd/rootwelld/renewal_timing_api.go" && filepath.ToSlash(relative) != "cmd/rootwelld/dns_operation_api.go" && filepath.ToSlash(relative) != "cmd/rootwelld/acme_directory_api.go" && filepath.ToSlash(relative) != "cmd/rootwelld/acme_registration_api.go" && filepath.ToSlash(relative) != "cmd/rootwelld/acme_order_api.go" && filepath.ToSlash(relative) != "internal/instanceaccess/acme_certificate_linux.go" && filepath.ToSlash(relative) != "internal/instanceaccess/acme_certificate_other.go" ||
					importPath == "golang.org/x/crypto/acme" && filepath.ToSlash(relative) != "internal/acmestaging/directory.go" && filepath.ToSlash(relative) != "internal/acmestaging/registration.go" && filepath.ToSlash(relative) != "internal/acmestaging/order.go" && filepath.ToSlash(relative) != "internal/acmestaging/validation.go" && filepath.ToSlash(relative) != "internal/acmestaging/certificate.go" {
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

func TestCloudflareProtocolHasOnlyReviewedFreshAuthConsumer(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "internal/acmestaging/cloudflare.go" {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() && fn.Name.Name != "CloudflareTXT" {
					t.Error("DNS protocol exported before custody", fn.Name.Name)
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "CloudflareTXT" && rel != "cmd/rootwelld/dns_operation_api.go" {
				t.Error("DNS connector outside fresh-auth transaction", rel)
			}
			if id, ok := node.(*ast.Ident); ok {
				switch id.Name {
				case "cloudflareRecord", "dnsRecordScope", "dnsRecordState", "dnsCommit", "cfSession", "cfDecodeRecord":
					if rel != "internal/acmestaging/cloudflare.go" {
						t.Error("unreviewed DNS protocol consumer", rel, id.Name)
					}
				case "pinnedTransportTo":
					if rel != "internal/acmestaging/cloudflare.go" && rel != "internal/acmestaging/directory.go" {
						t.Error("unreviewed fixed-host transport consumer", rel)
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

// Local key preparation remains covered separately. Only this new route gains
// the reviewed staging terms/register/find capability, never orders or URLs.
func TestStagingRegistrationHasOnlyReviewedAccountClientMethods(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	for path, methods := range map[string]map[string]bool{
		"internal/acmestaging/directory.go":    {"Discover": true},
		"internal/acmestaging/registration.go": {"Discover": true, "Register": true, "GetReg": true},
		"internal/acmestaging/order.go":        {"Discover": true, "AuthorizeOrder": true, "GetOrder": true, "GetAuthorization": true, "DNS01ChallengeRecord": true},
		"internal/acmestaging/validation.go":   {"Discover": true, "GetOrder": true, "GetAuthorization": true, "DNS01ChallengeRecord": true, "Accept": true},
		"internal/acmestaging/certificate.go":  {"Discover": true, "GetOrder": true, "GetAuthorization": true, "CreateOrderCert": true, "FetchCert": true},
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

func TestCloudflareCredentialCannotEscapeConfigurationBoundary(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && (id.Name == "cloudflarePayload" || id.Name == "cloudflareConfigKey") && relative != "internal/inventorystore/cloudflare_config.go" {
				t.Errorf("credential handling outside configuration boundary: %s", relative)
			}
			if ok && id.Name == "openCloudflareConfig" && relative != "internal/inventorystore/cloudflare_config.go" && relative != "internal/inventorystore/manifest.go" && relative != "internal/inventorystore/dns_plan.go" && relative != "internal/inventorystore/dns_operation.go" {
				t.Errorf("credential borrower before reviewed DNS lease: %s", relative)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDNSPlanCustodyHasOnlyReviewedLockedConsumers(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	allowed := map[string]bool{"internal/inventorystore/dns_plan.go": true, "internal/instanceaccess/dns_plan_linux.go": true, "internal/instanceaccess/dns_plan_other.go": true}
	allowed["internal/inventorystore/dns_operation.go"] = true
	allowed["internal/instanceaccess/dns_operation_linux.go"] = true
	allowed["internal/instanceaccess/dns_operation_other.go"] = true
	allowed["cmd/rootwelld/dns_operation_api.go"] = true
	exports := map[string]bool{"ReadStagingDNSPlan": true, "PrepareStagingDNSPlan": true, "BeginStagingDNSAttempt": true, "DeferStagingDNSAttempt": true}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		metadataOnly := relative == "internal/inventorystore/dns_plan.go"
		cleared := map[*ast.SelectorExpr]bool{}
		if metadataOnly {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if ok && fn.Name.IsExported() && !exports[fn.Name.Name] {
					t.Errorf("DNS plan exposes unreviewed authority: %s", fn.Name.Name)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if ok && id.Name == "clear" && len(call.Args) == 1 {
					if s, ok := call.Args[0].(*ast.SelectorExpr); ok && s.Sel.Name == "Token" {
						cleared[s] = true
					}
				}
				return true
			})
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if id.Name == "executeStagingDNSAttemptAt" && relative != "internal/inventorystore/dns_operation.go" || (id.Name == "beginDNSOperationAt" || id.Name == "deferStagingDNSAttemptAt") && relative != "internal/inventorystore/dns_plan.go" && relative != "internal/inventorystore/dns_operation.go" {
					t.Error("runtime DNS clock override", relative)
				}
				if (id.Name == "BeginStagingDNSOperation" || id.Name == "ExecuteStagingDNSAttempt") && relative != "internal/inventorystore/dns_operation.go" && relative != "internal/instanceaccess/dns_operation_linux.go" {
					t.Error("DNS route bypasses locked transaction", relative)
				}
				if id.Name == "RunStagingDNS" && relative != "internal/instanceaccess/dns_operation_linux.go" && relative != "internal/instanceaccess/dns_operation_other.go" && relative != "cmd/rootwelld/dns_operation_api.go" {
					t.Error("unreviewed DNS transaction consumer", relative)
				}
				if relative == "cmd/rootwelld/dns_operation_api.go" && (id.Name == "DNSAttempt" || id.Name == "PrepareStagingDNSPlan" || id.Name == "BeginStagingDNSAttempt" || id.Name == "DeferStagingDNSAttempt") {
					t.Error("DNS API invokes unlocked custody step", id.Name)
				}
			}
			if id, ok := n.(*ast.Ident); ok && (exports[id.Name] || id.Name == "DNSAttempt") && !allowed[relative] {
				t.Errorf("DNS intent wired before explicit reviewed route: %s", relative)
			}
			if s, ok := n.(*ast.SelectorExpr); ok && metadataOnly && s.Sel.Name == "Token" && !cleared[s] {
				t.Error("planning consumes a credential instead of only clearing validation bytes")
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertificateConnectorFixedStagingBoundary(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		connector := filepath.ToSlash(relative) == "internal/acmestaging/certificate.go"
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && connector && fn.Recv == nil && fn.Name.IsExported() && fn.Name.Name != "Certificate" {
				t.Errorf("live exported certificate capability before custody integration: %s", fn.Name.Name)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && !connector && (id.Name == "certificateOrder" || id.Name == "certificateTransport") {
				t.Errorf("certificate connector wired outside reviewed boundary: %s", relative)
			}
			if selector, ok := n.(*ast.SelectorExpr); ok && selector.Sel.Name == "Certificate" {
				if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "acmestaging" && filepath.ToSlash(relative) != "cmd/rootwelld/acme_order_api.go" {
					t.Errorf("certificate transport outside fresh-auth route: %s", relative)
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

func TestIssuanceExecutionReviewedBoundaries(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	allowed := map[string]bool{"internal/inventorystore/issuance.go": true, "internal/inventorystore/completion.go": true, "internal/instanceaccess/acme_completion_linux.go": true, "internal/instanceaccess/acme_completion_other.go": true, "internal/instanceaccess/acme_issuance_linux.go": true, "internal/instanceaccess/acme_issuance_other.go": true}
	allowed["internal/instanceaccess/acme_certificate_linux.go"] = true
	allowed["internal/instanceaccess/acme_certificate_other.go"] = true
	allowed["cmd/rootwelld/acme_order_api.go"] = true
	names := map[string]bool{"RunStagingIssuance": true, "WithStagingIssuance": true, "BeginStagingIssuance": true, "ObserveStagingIssuance": true, "FinishStagingIssuance": true, "finishStagingIssuance": true, "CompleteStagingIssuance": true}
	names["RunStagingCertificate"], names["runStagingCertificate"] = true, true
	names["ConstrainStagingIssuance"] = true
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if allowed[relative] && relative != "cmd/rootwelld/acme_order_api.go" {
				for _, imp := range file.Imports {
					p, err := strconv.Unquote(imp.Path.Value)
					if err != nil || forbiddenImport(p) || (p == "github.com/denyfirst/rootwell/internal/acmestaging" && relative != "internal/instanceaccess/acme_certificate_linux.go" && relative != "internal/instanceaccess/acme_certificate_other.go") || p == "golang.org/x/crypto/acme" {
						t.Errorf("live network authority in intent custody: %s", relative)
					}
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if ok && names[id.Name] && !allowed[relative] {
					t.Errorf("intent execution wired before pair/receipt/UI review: %s", relative)
				}
				if ok && names[id.Name] && relative == "cmd/rootwelld/acme_order_api.go" && id.Name != "RunStagingCertificate" {
					t.Errorf("route bypasses the locked transaction: %s", id.Name)
				}
				if ok && id.Name == "runStagingCertificate" && relative != "internal/instanceaccess/acme_certificate_linux.go" {
					t.Errorf("runtime receipt checker override: %s", relative)
				}
				if ok && id.Name == "finishStagingIssuance" && relative != "internal/inventorystore/completion.go" {
					t.Errorf("runtime pinned trust override: %s", relative)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCertificateTransactionProductionCompletionIsFixed(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(current), "..", "instanceaccess", "acme_certificate_linux.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "RunStagingCertificate" {
			continue
		}
		if len(fn.Body.List) != 1 {
			t.Fatal("production transaction must only forward to fixed acceptance")
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			t.Fatal("completion authority changed")
		}
		call, ok := ret.Results[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 9 {
			t.Fatal("completion authority changed")
		}
		selector, ok := call.Args[8].(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "FinishStagingIssuance" {
			t.Fatal("production checker not fixed")
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "inventorystore" {
			t.Fatal("production checker not fixed")
		}
		found = true
	}
	if !found {
		t.Fatal("fixed production transaction missing")
	}
}

func TestClosedRequestHistoryCannotBecomeNetworkOrRuntimeAuthority(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	allowedClose := map[string]bool{"internal/inventorystore/closed_requests.go": true, "internal/instanceaccess/acme_new_request_linux.go": true, "internal/instanceaccess/acme_new_request_other.go": true, "cmd/rootwelld/acme_order_api.go": true}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				if (ident.Name == "CloseStagingRequest" || ident.Name == "ReadNewStagingRequest") && !allowedClose[rel] {
					t.Errorf("unreviewed closed scope consumer: %s", rel)
				}
				if (ident.Name == "closedScope" || ident.Name == "openClosedRequest" || ident.Name == "closeStagingRequestAt") && rel != "internal/inventorystore/closed_requests.go" && !(ident.Name == "openClosedRequest" && rel == "internal/inventorystore/renewal.go") {
					t.Errorf("historical scope exported outside validator: %s", rel)
				}
				if ident.Name == "beginStagingOrderAt" && rel != "internal/inventorystore/orders.go" {
					t.Errorf("runtime new-order clock override: %s", rel)
				}
			}
			if sel, ok := node.(*ast.SelectorExpr); ok && sel.Sel.Name == "historical" && rel != "internal/inventorystore/closed_requests.go" && rel != "internal/inventorystore/issuance.go" && rel != "internal/inventorystore/dns_plan.go" && rel != "internal/inventorystore/dns_operation.go" {
				t.Errorf("historical flag outside bound validator: %s", rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManualRenewalConsumersStayInsideReviewedCustodyAndGate(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	allowed := map[string]map[string]bool{
		"BeginStagingRenewal":      {"internal/inventorystore/renewal.go": true, "internal/instanceaccess/acme_order_linux.go": true},
		"ReadStagingRenewalSource": {"internal/inventorystore/renewal.go": true, "internal/instanceaccess/acme_renewal_linux.go": true, "internal/instanceaccess/acme_renewal_other.go": true, "cmd/rootwelld/acme_renewal_navigation.go": true, "cmd/rootwelld/acme_order_api.go": true},
		"ReadStagingRenewalResult": {"internal/inventorystore/renewal_result.go": true, "internal/instanceaccess/acme_renewal_linux.go": true, "internal/instanceaccess/acme_renewal_other.go": true, "cmd/rootwelld/acme_order_api.go": true},
		"RunStagingRenewalOrder":   {"internal/instanceaccess/acme_order_linux.go": true, "internal/instanceaccess/acme_order_other.go": true, "cmd/rootwelld/acme_order_api.go": true},
		"runStagingOrder":          {"internal/instanceaccess/acme_order_linux.go": true},
		"renewalSource":            {"internal/inventorystore/renewal.go": true},
		"completedRenewalSources":  {"internal/inventorystore/renewal.go": true, "internal/inventorystore/automation_status.go": true, "internal/inventorystore/renewal_timing.go": true, "internal/inventorystore/renewal_timing_operation.go": true},
		"checkRenewalBinding":      {"internal/inventorystore/renewal.go": true, "internal/inventorystore/closed_requests.go": true},
		"renewalKeyFingerprint":    {"internal/inventorystore/renewal.go": true, "internal/inventorystore/closed_requests.go": true},
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				if files, guarded := allowed[ident.Name]; guarded && !files[rel] {
					t.Errorf("unreviewed renewal consumer: %s (%s)", rel, ident.Name)
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

func TestStagingReceiptHasNoNetworkStorageOrSigningAuthority(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	allowed := map[string]bool{"bytes": true, "crypto/rsa": true, "crypto/sha256": true, "crypto/x509": true,
		"embed": true, "encoding/asn1": true, "encoding/hex": true, "errors": true, "slices": true, "strings": true, "time": true,
		"github.com/denyfirst/rootwell/internal/acmecertrequest": true,
		"github.com/denyfirst/rootwell/internal/certinspect":     true, "github.com/denyfirst/rootwell/internal/certverify": true}
	for _, path := range []string{"internal/acmecertificate/check.go", "internal/acmecertificate/trust.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil || !allowed[value] || (imported.Name != nil && !(value == "embed" && imported.Name.Name == "_")) {
				t.Errorf("unreviewed receipt import in %s: %s", path, imported.Path.Value)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			s, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := s.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "acmecertrequest":
				if s.Sel.Name != "Check" {
					t.Errorf("receipt gained key generation/signing: %s", s.Sel.Name)
				}
			case "x509":
				if s.Sel.Name != "ParseCertificateRequest" && s.Sel.Name != "NewCertPool" {
					t.Errorf("unreviewed X.509 receipt operation: %s", s.Sel.Name)
				}
			case "certverify":
				if s.Sel.Name != "CheckCertificatePolicy" && s.Sel.Name != "ParseTrustAnchors" {
					t.Errorf("unreviewed receipt trust operation: %s", s.Sel.Name)
				}
			case "asn1":
				if s.Sel.Name != "Unmarshal" {
					t.Errorf("receipt gained ASN.1 generation: %s", s.Sel.Name)
				}
			}
			return true
		})
	}
}
