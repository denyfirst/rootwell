package uicontract

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"
)

// The files the gate serves from web/workbench, apart from the engine and its
// runtime, which are built at release.
var pageAssetNames = []string{
	"certificates.html", "certificates.js", "inspect.html", "inspect.js", "convert.html", "convert.js",
	"request.html", "request.js", "ui.js", "rootwell.css", "style.css", "theme.js", "session.js", "favicon.svg",
	"wasm-loader.js", "private-worker-client.js", "private-key-worker.js", "pfx-worker-client.js", "pfx-worker.js",
	"csr-worker-client.js", "csr-worker.js",
}

func pageAssets(t *testing.T) map[string]string {
	t.Helper()
	assets := make(map[string]string, len(pageAssetNames))
	for _, name := range pageAssetNames {
		assets[name] = repositoryFile(t, "web", "workbench", name)
	}
	return assets
}

// Every page and script comes from this server: no remote file, no inline
// script and no inline event handler, so the server's policy can forbid both.
func TestPagesAreSelfContained(t *testing.T) {
	for name, content := range pageAssets(t) {
		if len(content) == 0 || len(content) > 1<<20 {
			t.Errorf("asset %q size = %d, want 1..1048576", name, len(content))
		}
	}
	remoteReference := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["'](?:https?:|//)`)
	inlineScript := regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>\s*[^<\s]`)
	for name, page := range designedPages(t) {
		if remoteReference.MatchString(page) {
			t.Errorf("%s loads a file from another server", name)
		}
		if inlineScript.MatchString(page) || regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(page) {
			t.Errorf("%s carries inline script or an inline event handler", name)
		}
		for _, src := range regexp.MustCompile(`<script[^>]*>`).FindAllString(page, -1) {
			if !regexp.MustCompile(`^<script src="/[a-z0-9_-]+\.js"( defer)?>$`).MatchString(src) {
				t.Errorf("%s loads a script other than one of its own: %s", name, src)
			}
		}
	}
}

// The scripts that read the files a person chooses have no network, storage,
// worker or HTML-writing capability of their own; the engine loader fetches
// only the engine; each worker client runs one bounded, cancellable worker
// that clears what it was given.
func TestPagesSeparateFileAndNetworkCapabilities(t *testing.T) {
	assets := pageAssets(t)
	fileReading := map[string]string{"inspect.js": assets["inspect.js"], "convert.js": assets["convert.js"],
		"request.js": assets["request.js"], "ui.js": assets["ui.js"]}
	for name, script := range fileReading {
		for _, forbidden := range []string{
			"fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",
			"serviceWorker", "Worker(", "SharedWorker", "import(",
			"FileReader", "readAs", "indexedDB", "caches.", "localStorage", "sessionStorage",
			"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
		} {
			if strings.Contains(script, forbidden) {
				t.Errorf("%s reads files and must not use %q", name, forbidden)
			}
		}
	}
	// Certificates talks to its own API, and nothing else; the API calls are
	// listed by scripts/test-certificates.mjs.
	for _, forbidden := range []string{"XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "serviceWorker", "SharedWorker",
		"import(", "FileReader", "indexedDB", "caches.", "localStorage", "sessionStorage",
		"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "https://", "http://"} {
		if strings.Contains(assets["certificates.js"], forbidden) {
			t.Errorf("certificates.js must not use %q", forbidden)
		}
	}
	// The colour scheme script remembers one choice and touches no file.
	for _, forbidden := range []string{"fetch(", "XMLHttpRequest", ".files", "arrayBuffer", "FileReader", "innerHTML", "eval("} {
		if strings.Contains(assets["theme.js"], forbidden) {
			t.Errorf("theme.js must not use %q", forbidden)
		}
	}

	loader := assets["wasm-loader.js"]
	for _, forbidden := range []string{"document", "querySelector", ".files", "FileReader", "Uint8Array", "dataTransfer", "inspect-file", "serviceWorker", "Worker(", "SharedWorker", "import("} {
		if strings.Contains(loader, forbidden) {
			t.Errorf("WebAssembly asset loader contains file/DOM capability %q", forbidden)
		}
	}
	for _, required := range []string{
		`fetch("rootwell.wasm"`, "module: wasmModule", "rootwellExplore", "rootwellExport",
		`credentials: "omit"`, `redirect: "error"`, "WebAssembly.instantiateStreaming", "WebAssembly.instantiate(bytes",
	} {
		if !strings.Contains(loader, required) {
			t.Errorf("WebAssembly loader is missing restriction %q", required)
		}
	}

	workers := []struct {
		name, client, worker string
		required             []string
	}{
		{"private key", "private-worker-client.js", "private-key-worker.js", []string{`new Worker("private-key-worker.js"`,
			`setTimeout(function () { finish(true); }`, "worker.terminate()", `signal.addEventListener("abort"`, "source.fill(0)",
			"current.fill(0)", "output.fill(0)", `importScripts("wasm_exec.js")`, "WebAssembly.instantiate(request.module", "input.fill(0)",
			"currentPassword.fill(0)", "outputPassword.fill(0)", "self.rootwellPrivateInspect", "self.rootwellPrivateExport"}},
		{"PFX", "pfx-worker-client.js", "pfx-worker.js", []string{`new Worker("pfx-worker.js"`, "worker.terminate()",
			`signal.addEventListener("abort"`, `importScripts("wasm_exec.js")`, "self.rootwellPFXInspect", "self.rootwellPFXOutput", "bytes.fill(0)"}},
		{"CSR and key match", "csr-worker-client.js", "csr-worker.js", []string{`new Worker("csr-worker.js"`, "worker.terminate()",
			`signal.addEventListener("abort"`, `importScripts("wasm_exec.js")`, "bytes.fill(0)", "180000", "90000", "30000",
			"self.rootwellCertificateKeyMatch"}},
	}
	for _, w := range workers {
		path := assets[w.client] + "\n" + assets[w.worker]
		for _, forbidden := range []string{"fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "localStorage", "sessionStorage", "indexedDB", "console.", "document", "innerHTML", "eval(", "https://", "http://"} {
			if strings.Contains(path, forbidden) {
				t.Errorf("%s worker path contains forbidden capability %q", w.name, forbidden)
			}
		}
		for _, required := range w.required {
			if !strings.Contains(path, required) {
				t.Errorf("%s worker path lacks boundary %q", w.name, required)
			}
		}
	}
}

// Inspect says how many files it takes, and takes exactly that many.
func TestInspectFileHintMatchesItsLimit(t *testing.T) {
	assets := pageAssets(t)
	if !strings.Contains(assets["inspect.html"], "PEM, CRT, CER or DER, up to 8 files") ||
		!strings.Contains(assets["inspect.html"], `id="inspect-file" type="file" multiple accept=".pem,.crt,.cer,.der,.txt,.ca-bundle"`) {
		t.Error("Inspect does not say which files it takes")
	}
	if !strings.Contains(assets["inspect.js"], "const maxFiles = 8;") {
		t.Error("Inspect takes a different number of files than it says")
	}
	if !strings.Contains(assets["inspect.html"], "It never leaves this browser.") {
		t.Error("Inspect does not say that files stay in this browser")
	}
}

// Every element a page or its script names exists, once.
func TestPageElementReferencesResolve(t *testing.T) {
	assets := pageAssets(t)
	idPattern := regexp.MustCompile(`\sid="([A-Za-z][A-Za-z0-9_-]*)"`)
	referencePattern := regexp.MustCompile(`(?:for|aria-controls|aria-labelledby|aria-describedby)="([A-Za-z][A-Za-z0-9_-]*)"`)
	lookupPattern := regexp.MustCompile(`(?:getElementById|\$)\("([A-Za-z][A-Za-z0-9_-]*)"\)`)
	assignedPattern := regexp.MustCompile(`\.id = "([A-Za-z][A-Za-z0-9_-]*)"`)
	for _, page := range []string{"certificates", "inspect", "convert", "request"} {
		html, script := assets[page+".html"], assets[page+".js"]
		ids := make(map[string]bool)
		for _, match := range idPattern.FindAllStringSubmatch(html, -1) {
			if ids[match[1]] {
				t.Errorf("%s.html: duplicate element id %q", page, match[1])
			}
			ids[match[1]] = true
		}
		for _, match := range assignedPattern.FindAllStringSubmatch(script, -1) {
			ids[match[1]] = true
		}
		for _, match := range referencePattern.FindAllStringSubmatch(html, -1) {
			if !ids[match[1]] {
				t.Errorf("%s.html: reference %q has no element", page, match[1])
			}
		}
		lookups := lookupPattern.FindAllStringSubmatch(script, -1)
		if len(lookups) < 5 {
			t.Errorf("%s.js: only %d element lookups were found, which is too few to be right", page, len(lookups))
		}
		for _, match := range lookups {
			if !ids[match[1]] {
				t.Errorf("%s.js looks up %q, which %s.html does not have", page, match[1], page)
			}
		}
	}
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
