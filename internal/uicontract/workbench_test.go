package uicontract

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/browserexplore"
	"github.com/denyfirst/rootwell/internal/browserexport"
	"github.com/denyfirst/rootwell/internal/browserinspect"
	"github.com/denyfirst/rootwell/internal/browserverifiedexport"
	"github.com/denyfirst/rootwell/internal/browserverify"
)

var workbenchAssetNames = []string{
	"index.html", "style.css", "theme.js", "wasm-loader.js", "app.js", "favicon.svg",
	"rootwell-demo-certificate.pem", "rootwell-demo-bundle.pem",
	"rootwell-verify-demo-leaf.pem", "rootwell-verify-demo-intermediate.pem",
	"rootwell-verify-demo-root.pem", "rootwell-verify-demo-ca-files.pem",
}

func TestWorkbenchPreviewIsSelfContained(t *testing.T) {
	assets := workbenchAssets(t)
	for _, name := range workbenchAssetNames {
		content, exists := assets[name]
		if !exists {
			t.Fatalf("required asset %q is missing", name)
		}
		if len(content) == 0 || len(content) > 1<<20 {
			t.Fatalf("asset %q size = %d, want 1..1048576", name, len(content))
		}
	}

	html := assets["index.html"]
	remoteReference := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["'](?:https?:|//)`)
	if remoteReference.MatchString(html) {
		t.Fatal("workbench HTML contains a remote subresource")
	}
	if regexp.MustCompile(`(?i)\sstyle\s*=`).MatchString(html) || regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(html) {
		t.Fatal("workbench HTML contains inline style or event-handler code")
	}
}

func TestWorkbenchDemoCertificateIsPublicAndInspectable(t *testing.T) {
	certificate := workbenchAssets(t)["rootwell-demo-certificate.pem"]
	if strings.Contains(certificate, "PRIVATE KEY") || !strings.Contains(certificate, "-----BEGIN CERTIFICATE-----") {
		t.Fatal("demo input must contain one public certificate and no private key")
	}
	var response browserinspect.Response
	if err := json.Unmarshal([]byte(browserinspect.Process([]byte(certificate), time.Unix(1_800_000_000, 0))), &response); err != nil {
		t.Fatalf("inspect demo certificate: %v", err)
	}
	if !response.OK || response.Result == nil || response.Error != nil {
		t.Fatalf("demo certificate response = %#v, want success", response)
	}
	var explored browserexplore.Response
	if err := json.Unmarshal([]byte(browserexplore.Process([]byte(certificate))), &explored); err != nil {
		t.Fatalf("explore demo certificate: %v", err)
	}
	if !explored.OK || explored.Result == nil || explored.Result.Count != 1 || explored.Result.Verification != "not-performed" {
		t.Fatalf("demo certificate exploration = %#v, want unverified success", explored)
	}
}

func TestWorkbenchDemoBundleIsPublicAndExplorable(t *testing.T) {
	bundle := workbenchAssets(t)["rootwell-demo-bundle.pem"]
	if strings.Contains(bundle, "PRIVATE KEY") || strings.Count(bundle, "-----BEGIN CERTIFICATE-----") != 2 {
		t.Fatal("demo bundle must contain exactly two public certificates and no private key")
	}
	var response browserexplore.Response
	if err := json.Unmarshal([]byte(browserexplore.Process([]byte(bundle))), &response); err != nil {
		t.Fatalf("explore demo bundle: %v", err)
	}
	if !response.OK || response.Error != nil || response.Result == nil || response.Result.Count != 2 ||
		response.Result.Certificates[0].SHA256 == response.Result.Certificates[1].SHA256 {
		t.Fatalf("demo bundle response = %#v, want two different certificates", response)
	}
	for _, encoding := range []string{"pem", "der"} {
		exported, code := browserexport.Prepare([]byte(bundle), response.Result.Certificates[1].SHA256, encoding)
		if code != "" {
			t.Fatalf("export demo certificate as %s: %s", encoding, code)
		}
		var single browserexplore.Response
		if err := json.Unmarshal([]byte(browserexplore.Process(exported.Bytes)), &single); err != nil {
			t.Fatal(err)
		}
		if !single.OK || single.Result == nil || single.Result.Count != 1 || single.Result.Certificates[0].SHA256 != response.Result.Certificates[1].SHA256 {
			t.Fatalf("exported demo certificate = %#v", single)
		}
		clear(exported.Bytes)
	}
}

func TestWorkbenchVerifyDemoIsPublicAndExportsOnlyVerifiedPath(t *testing.T) {
	assets := workbenchAssets(t)
	for _, name := range []string{
		"rootwell-verify-demo-leaf.pem", "rootwell-verify-demo-intermediate.pem",
		"rootwell-verify-demo-root.pem", "rootwell-verify-demo-ca-files.pem",
	} {
		if strings.Contains(assets[name], "PRIVATE KEY") || strings.Contains(assets[name], "PASSWORD") {
			t.Fatalf("%s is not public-only", name)
		}
	}
	leaf := assets["rootwell-verify-demo-leaf.pem"]
	intermediate := assets["rootwell-verify-demo-intermediate.pem"]
	root := assets["rootwell-verify-demo-root.pem"]
	source := assets["rootwell-verify-demo-ca-files.pem"]
	if source != leaf+intermediate+root {
		t.Fatal("demo CA files differ from their separate public parts")
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var verified browserverify.Response
	if err := json.Unmarshal([]byte(browserverify.Simple([][]byte{[]byte(source)}, []byte(root),
		"verify.rootwell.invalid", now)), &verified); err != nil || !verified.OK || verified.Result == nil {
		t.Fatalf("demo verification: %v, %#v", err, verified)
	}
	if len(verified.Result.Chain) != 3 || verified.Result.IgnoredSourceRoots != 1 {
		t.Fatalf("demo verified chain = %#v", verified.Result)
	}
	var expected []string
	for _, member := range verified.Result.Chain {
		expected = append(expected, member.SHA256Fingerprint)
	}
	output, code := browserverifiedexport.PrepareSimple([][]byte{[]byte(source)}, []byte(root),
		"verify.rootwell.invalid", now, expected)
	if code != "" {
		t.Fatalf("demo verified export: %s", code)
	}
	defer clear(output.Bytes)
	if string(output.Bytes) != leaf+intermediate || strings.Contains(string(output.Bytes), root) {
		t.Fatal("demo fullchain did not preserve leaf/intermediate order or included root")
	}
}

func TestWorkbenchContentSecurityPolicyRestrictsConnections(t *testing.T) {
	html := workbenchAssets(t)["index.html"]
	for _, directive := range []string{
		"default-src 'none'",
		"style-src 'self'",
		"script-src 'self' 'wasm-unsafe-eval'",
		"img-src 'self'",
		"connect-src 'self'",
		"font-src 'none'",
		"object-src 'none'",
		"worker-src 'none'",
		"manifest-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
	} {
		if !strings.Contains(html, directive) {
			t.Errorf("Content Security Policy is missing %q", directive)
		}
	}
	if strings.Contains(html, "script-src 'self' 'unsafe-eval'") || strings.Contains(html, "'unsafe-inline'") {
		t.Fatal("Content Security Policy enables dynamic JavaScript execution")
	}
}

func TestWorkbenchTextContrast(t *testing.T) {
	css := workbenchAssets(t)["style.css"]
	themes := []struct {
		name   string
		paper  string
		sunk   string
		ink    string
		soft   string
		faint  string
		brand  string
		accent string
		good   string
	}{
		{name: "light", paper: "#f7f7f8", sunk: "#ececf0", ink: "#16171b", soft: "#464953", faint: "#5c606a", brand: "#c42b3a", accent: "#b3202e", good: "#1f6a44"},
		{name: "dark", paper: "#101114", sunk: "#18191d", ink: "#f0f0f2", soft: "#b4b5be", faint: "#999ba6", brand: "#ed4552", accent: "#c72f3d", good: "#6fbf92"},
	}
	for _, theme := range themes {
		for _, token := range []string{theme.paper, theme.sunk, theme.ink, theme.soft, theme.faint, theme.brand, theme.accent, theme.good} {
			if !strings.Contains(css, token) {
				t.Errorf("%s theme token %s is absent from CSS", theme.name, token)
			}
		}
		pairs := []struct {
			name       string
			foreground string
			background string
		}{
			{name: "ink on paper", foreground: theme.ink, background: theme.paper},
			{name: "soft on paper", foreground: theme.soft, background: theme.paper},
			{name: "faint on paper", foreground: theme.faint, background: theme.paper},
			{name: "ink on sunk", foreground: theme.ink, background: theme.sunk},
			{name: "soft on sunk", foreground: theme.soft, background: theme.sunk},
			{name: "faint on sunk", foreground: theme.faint, background: theme.sunk},
			{name: "brand on paper", foreground: theme.brand, background: theme.paper},
			{name: "good on paper", foreground: theme.good, background: theme.paper},
			{name: "white on accent", foreground: "#ffffff", background: theme.accent},
		}
		for _, pair := range pairs {
			if ratio := contrastRatio(t, pair.foreground, pair.background); ratio < 4.5 {
				t.Errorf("%s %s contrast = %.2f, want at least 4.5", theme.name, pair.name, ratio)
			}
		}
	}
}

func TestWorkbenchSeparatesFileAndNetworkCapabilities(t *testing.T) {
	assets := workbenchAssets(t)
	application := assets["app.js"]
	loader := assets["wasm-loader.js"]
	fileReadingScripts := application + "\n" + assets["theme.js"]
	for _, forbidden := range []string{
		"fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",
		"serviceWorker", "Worker(", "SharedWorker", "import(",
		"FileReader", "readAs", "indexedDB", "caches.",
		"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
	} {
		if strings.Contains(fileReadingScripts, forbidden) {
			t.Errorf("file-reading workbench script contains forbidden capability %q", forbidden)
		}
	}
	if strings.Contains(application, "localStorage") || strings.Contains(application, "sessionStorage") {
		t.Fatal("application script persists workbench input")
	}
	for _, required := range []string{"selectedInspectFile.arrayBuffer()", "engine.inspect(bytes)", "engine.explore(bytes)", "bytes.fill(0)", ".textContent ="} {
		if !strings.Contains(application, required) {
			t.Errorf("application script is missing local-processing guard %q", required)
		}
	}

	for _, forbidden := range []string{"document", "querySelector", ".files", "FileReader", "Uint8Array", "dataTransfer", "inspect-file", "serviceWorker", "Worker(", "SharedWorker", "import("} {
		if strings.Contains(loader, forbidden) {
			t.Errorf("WebAssembly asset loader contains file/DOM capability %q", forbidden)
		}
	}
	for _, required := range []string{
		`fetch("rootwell.wasm"`,
		"rootwellExplore",
		"rootwellExport",
		`credentials: "omit"`,
		`redirect: "error"`,
		"WebAssembly.instantiateStreaming",
		"WebAssembly.instantiate(bytes",
	} {
		if !strings.Contains(loader, required) {
			t.Errorf("WebAssembly loader is missing restriction %q", required)
		}
	}
}

func TestWorkbenchProcessingClaimsAreBounded(t *testing.T) {
	html := workbenchAssets(t)["index.html"]
	for _, statement := range []string{
		"Certificate bytes stay inside this browser process",
		"Local inspection · not a trust verdict",
		"Local exploration · not a trust verdict",
		"No chain verification performed · no trust anchor selected",
		"do not prove chain trust",
		"Revocation</strong> Not checked",
		"System roots</strong> Not used",
	} {
		if !strings.Contains(html, statement) {
			t.Errorf("workbench preview is missing boundary statement %q", statement)
		}
	}
}

func TestWorkbenchExploreIsPublicOnlyAndFunctional(t *testing.T) {
	assets := workbenchAssets(t)
	html := assets["index.html"]
	for _, required := range []string{
		`id="explore-tab" data-tool="explore"`,
		`id="explore-file" multiple accept=".pem,.cer,.crt,.der,application/x-x509-ca-cert"`,
		"1–8 files · 1–64 certificates · 16 MiB combined",
		"duplicate certificates across files are rejected",
		"Private keys and PFX are not supported",
		`href="rootwell-demo-bundle.pem" download`,
		"The CA flag and possible issuer links are public-certificate evidence, not proof that a root is trusted",
		`id="explore-result" aria-live="polite" hidden`,
		`id="explore-expiry-summary"`,
		`id="explore-health-summary"`,
		`id="explore-links-list" aria-label="Possible public certificate signing links"`,
		`id="explore-report-button" type="button" disabled`,
		`id="explore-report-status" aria-live="polite"`,
		`id="explore-report-error" role="alert" hidden`,
		`id="explore-verify-button" type="button" disabled`,
		"Explore only the CA files, then continue to Verify",
		"Nothing here is trusted yet",
		`id="explore-expiry-list" aria-label="Public certificates ordered by expiry"`,
		"A date window is not a trust, revocation, deployment, or renewal verdict",
	} {
		if !strings.Contains(html, required) {
			t.Errorf("Explore is missing boundary %q", required)
		}
	}
	application := assets["app.js"]
	for _, required := range []string{
		"file.arrayBuffer()", "engine.explore(bytes)", "validExploreResult(response.result)",
		"exploreCertificates.replaceChildren(...cards)", "description.textContent = value", "bytes.fill(0)",
		"if (files.length > maxExploreFiles) {", "remainingBytes -= bytes.byteLength",
		"fingerprints.get(certificate.sha256)", "selectedFileLabel(previous.file, previous.index)",
		"selectedFileLabel(file, fileIndex)", "entries.length === maxExploreCertificates",
		"metadataBytes > maxExploreMetadataBytes", "engine.analyze(analysisInputs)",
		"validChainResult(analysis, entries)", "renderExplore(entries, analysis.result)",
		"bundleDetail(details, \"Source file\", displayFileName(entry.file))",
		"validUTCSecond(certificate.not_before)", "validUTCSecond(certificate.not_after)",
		"renderExpiryOverview(entries, now)", "clearExpiryOverview()",
		"renderHealthGuide(entries, chain)", "renderPossibleLinks(entries, chain)", "clearPossibleLinks()",
		"downloadPublicReport()", "rootwell.public-health-report.v1",
		"guidedVerifyFingerprints", "clearGuidedVerifyFiles()",
	} {
		if !strings.Contains(application, required) {
			t.Errorf("Explore is missing local-processing guard %q", required)
		}
	}
	if strings.Contains(html, "Explore and verify") || strings.Contains(html, "Download selected certificate") {
		t.Error("Explore advertises verification or export that is not implemented")
	}
}

func TestWorkbenchPublicExportIsLocalAndExplicit(t *testing.T) {
	assets := workbenchAssets(t)
	html := assets["index.html"]
	for _, required := range []string{
		`id="export-status" aria-live="polite"`,
		`id="export-error" role="alert" hidden`,
		"Choose the certificate encoding and filename extension",
		"A .crt or .cer name can contain PEM or DER",
		"Rootwell does not write directly to disk",
	} {
		if !strings.Contains(html, required) {
			t.Errorf("public export is missing boundary %q", required)
		}
	}
	application := assets["app.js"]
	for _, required := range []string{
		`exportAction(entry.file, certificate.sha256, index)`,
		`selectedExploreFiles.includes(file)`,
		`"pem:pem": Object.freeze({ encoding: "pem", extension: "pem"`,
		`"pem:crt": Object.freeze({ encoding: "pem", extension: "crt"`,
		`"pem:cer": Object.freeze({ encoding: "pem", extension: "cer"`,
		`"der:der": Object.freeze({ encoding: "der", extension: "der"`,
		`"der:crt": Object.freeze({ encoding: "der", extension: "crt"`,
		`"der:cer": Object.freeze({ encoding: "der", extension: "cer"`,
		`Object.hasOwn(exportChoices, choice.value)`,
		`Object.hasOwn(exportChoices, format + ":" + extension)`,
		`downloadName = validated.filename.slice(0, -format.length) + extension`,
		"engine.exportPublic(input, fingerprint, format)",
		"engine.explore(output)",
		"URL.createObjectURL(new Blob([bytes]",
		"URL.revokeObjectURL(url)",
		"anchor.download = filename",
		"input.fill(0)", "output.fill(0)",
	} {
		if !strings.Contains(application, required) {
			t.Errorf("public export is missing guard %q", required)
		}
	}
	if strings.Contains(application, "showSaveFilePicker") || strings.Contains(application, "createWritable") {
		t.Error("browser export must not write through a filesystem API")
	}
	for _, forbidden := range []string{`"pem:der"`, `"der:pem"`} {
		if strings.Contains(application, forbidden) {
			t.Errorf("export offers an encoding/extension mismatch %q", forbidden)
		}
	}
}

func TestWorkbenchPublicBundleExportIsExplicit(t *testing.T) {
	assets := workbenchAssets(t)
	html := assets["index.html"]
	for _, required := range []string{
		`id="export-bundle-button" type="button" disabled`,
		"Download selected PEM bundle",
		"This does not build or verify a chain; no private key is included",
	} {
		if !strings.Contains(html, required) {
			t.Errorf("public bundle export is missing boundary %q", required)
		}
	}
	application := assets["app.js"]
	for _, required := range []string{
		"selectedBundleFingerprints.size === 0",
		"engine.exportBundle(inputs, expected, selected)",
		"validateBundleExportResponse",
		"result.fingerprints.every",
		"certificate.sha256 === selected[index] && certificate.encoding === \"pem\"",
		"for (const bytes of inputs) bytes.fill(0)",
		"requestBrowserDownload(output, validated.filename)",
	} {
		if !strings.Contains(application, required) {
			t.Errorf("public bundle export is missing guard %q", required)
		}
	}
}

func TestWorkbenchInspectFileHintMatchesParserBoundary(t *testing.T) {
	html := workbenchAssets(t)["index.html"]
	for _, required := range []string{
		`accept=".pem,.cer,.crt,.der,application/x-x509-ca-cert"`,
		"Choose a certificate file (.pem, .crt, .cer, .der)",
		"one certificate · maximum 16 MiB",
		"Its content must be PEM or DER; bundles and PFX are not supported here",
	} {
		if !strings.Contains(html, required) {
			t.Errorf("Inspect file hint is missing boundary %q", required)
		}
	}
	if strings.Contains(html, "Any type") || strings.Contains(html, "All formats") {
		t.Error("Inspect advertises unsupported input formats")
	}
}

func TestWorkbenchVerifyRequiresExplicitTrustAndRemovesPreview(t *testing.T) {
	assets := workbenchAssets(t)
	html := assets["index.html"]
	start := strings.Index(html, `<section class="tool-panel" id="verify-panel"`)
	if start < 0 {
		t.Fatal("verify panel boundary is missing")
	}
	end := strings.Index(html[start:], `    </main>`)
	if end < 0 {
		t.Fatal("verify panel boundary is missing")
	}
	panel := html[start : start+end]
	for _, forbidden := range []string{"Preview only", "Show sample result", "Sample data · offline TLS server profile"} {
		if strings.Contains(panel, forbidden) {
			t.Errorf("Verify still contains preview copy %q", forbidden)
		}
	}
	for _, required := range []string{
		`id="verify-hostname"`, `id="verify-trust-file"`, `id="verify-root-pin"`,
		`id="verify-source-files"`, `id="verify-leaf-file"`,
		`id="verify-guided-source"`, `id="verify-next-step"`,
		`id="verify-intermediates-file"`, `id="verify-time"`,
		`id="verify-button" type="button" disabled`,
		`id="verify-export-button" type="button" disabled`,
		`href="rootwell-verify-demo-ca-files.pem" download`,
		`href="rootwell-verify-demo-root.pem" download`,
		"A root found in your CA's other files is never trusted automatically",
		"Copying the fingerprint from the same file proves nothing extra",
		"Without a pin, root identity is unconfirmed",
		"Self-signed roots in these files are ignored, not trusted",
		"No OCSP, CRL, Certificate Transparency, private-key possession, or live endpoint check",
	} {
		if !strings.Contains(panel, required) {
			t.Errorf("Verify is missing user boundary %q", required)
		}
	}
	application := assets["app.js"]
	for _, required := range []string{
		"engine.verifySimple(", "engine.verifyExplicit(",
		"engine.exportVerifiedSimple(", "engine.exportVerifiedExplicit(",
		"validVerifyResponse(response, hostname, rootPin)",
		"verifyGeneration++", "verifyResult.hidden = true",
		"for (const bytes of buffers) bytes.fill(0)",
		"certificate.sha256 === expected[position]", "verifyNextSteps", "guidedVerifyFiles || verifySourceFiles.files",
	} {
		if !strings.Contains(application, required) {
			t.Errorf("Verify is missing local guard %q", required)
		}
	}
}

func TestWorkbenchElementReferencesResolve(t *testing.T) {
	html := workbenchAssets(t)["index.html"]
	idPattern := regexp.MustCompile(`\sid="([A-Za-z][A-Za-z0-9_-]*)"`)
	ids := make(map[string]struct{})
	for _, match := range idPattern.FindAllStringSubmatch(html, -1) {
		if _, exists := ids[match[1]]; exists {
			t.Errorf("duplicate element id %q", match[1])
		}
		ids[match[1]] = struct{}{}
	}

	referencePattern := regexp.MustCompile(`(?:for|aria-controls|data-drop-target|data-show-sample)="([A-Za-z][A-Za-z0-9_-]*)"`)
	for _, match := range referencePattern.FindAllStringSubmatch(html, -1) {
		if _, exists := ids[match[1]]; !exists {
			t.Errorf("element reference %q has no matching id", match[1])
		}
	}
}

func workbenchAssets(t *testing.T) map[string]string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate UI contract test")
	}
	directory := filepath.Join(filepath.Dir(currentFile), "..", "..", "web", "workbench")
	assets := make(map[string]string)
	for _, name := range workbenchAssetNames {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		assets[name] = string(content)
	}
	return assets
}

func contrastRatio(t *testing.T, foreground, background string) float64 {
	t.Helper()
	lighter := relativeLuminance(t, foreground)
	darker := relativeLuminance(t, background)
	if lighter < darker {
		lighter, darker = darker, lighter
	}
	return (lighter + 0.05) / (darker + 0.05)
}

func relativeLuminance(t *testing.T, value string) float64 {
	t.Helper()
	var red, green, blue uint8
	if _, err := fmt.Sscanf(value, "#%02x%02x%02x", &red, &green, &blue); err != nil {
		t.Fatalf("parse color %q: %v", value, err)
	}
	channel := func(component uint8) float64 {
		linear := float64(component) / 255
		if linear <= 0.04045 {
			return linear / 12.92
		}
		return math.Pow((linear+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(red) + 0.7152*channel(green) + 0.0722*channel(blue)
}
