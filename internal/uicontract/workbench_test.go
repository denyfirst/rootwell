package uicontract

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestWorkbenchPreviewIsSelfContained(t *testing.T) {
	assets := workbenchAssets(t)
	for _, name := range []string{"index.html", "style.css", "theme.js", "app.js", "favicon.svg"} {
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

func TestWorkbenchContentSecurityPolicyDeniesNetwork(t *testing.T) {
	html := workbenchAssets(t)["index.html"]
	for _, directive := range []string{
		"default-src 'none'",
		"style-src 'self'",
		"script-src 'self'",
		"img-src 'self'",
		"connect-src 'none'",
		"font-src 'none'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
	} {
		if !strings.Contains(html, directive) {
			t.Errorf("Content Security Policy is missing %q", directive)
		}
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

func TestWorkbenchScriptCannotReadOrTransmitFiles(t *testing.T) {
	assets := workbenchAssets(t)
	application := assets["app.js"]
	combined := application + "\n" + assets["theme.js"]
	for _, forbidden := range []string{
		"fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",
		"FileReader", "arrayBuffer(", "readAs", "indexedDB", "caches.",
		"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("workbench script contains forbidden capability %q", forbidden)
		}
	}
	if strings.Contains(application, "localStorage") || strings.Contains(application, "sessionStorage") {
		t.Fatal("application script persists workbench input")
	}
	if !strings.Contains(application, "output.textContent = file ?") || !strings.Contains(application, "output.textContent = file.name") {
		t.Fatal("file metadata must be rendered through textContent")
	}
}

func TestWorkbenchPreviewDoesNotClaimRealProcessing(t *testing.T) {
	html := workbenchAssets(t)["index.html"]
	for _, statement := range []string{
		"This preview does not read file bytes",
		"Sample data · not your selected file",
		"Preview mode — no certificate parsing in this browser build",
		"Revocation</strong> Not checked",
		"System roots</strong> Not used",
	} {
		if !strings.Contains(html, statement) {
			t.Errorf("workbench preview is missing boundary statement %q", statement)
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
	for _, name := range []string{"index.html", "style.css", "theme.js", "app.js", "favicon.svg"} {
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
