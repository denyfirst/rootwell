package uicontract

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// fontSHA256 is the typeface Porch chose and Keybash pins: Schibsted Grotesk,
// the variable Latin subset from @fontsource-variable/schibsted-grotesk 5.3.0.
// A font is a program a browser parses, so a different file is a decision
// somebody writes down here, never a side effect.
const fontSHA256 = "4c8b93f431d462c696e12b9d6a033feb3394d36e66e781357c496b95d8a75e05"

// The ratio text needs at the sizes these pages use.
const readableContrast = 4.5

func repositoryFile(t *testing.T, parts ...string) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate the UI contract test")
	}
	path := filepath.Join(append([]string{filepath.Dir(current), "..", ".."}, parts...)...)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(content)
}

// The sheets every page draws with: the workspace sheet and the sign-in sheet,
// plus the page sheets that build on the workspace one.
func designSheets(t *testing.T) map[string]string {
	return map[string]string{
		"style.css":     repositoryFile(t, "web", "workbench", "style.css"),
		"auth.css":      repositoryFile(t, "cmd", "rootwelld", "auth", "auth.css"),
		"inventory.css": repositoryFile(t, "cmd", "rootwelld", "auth", "inventory.css"),
	}
}

var (
	tokenPattern      = regexp.MustCompile(`--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;`)
	textColourPattern = regexp.MustCompile(`(?m)(?:^|[;{\s])color:\s*var\(--([a-z-]+)\)`)
)

// schemes returns a sheet's tokens in light and dark: dark is light with the
// dark block's overrides, as a browser resolves it.
func schemes(t *testing.T, name, sheet string) map[string]map[string]string {
	t.Helper()
	block := func(from string) string {
		start := strings.Index(sheet, from)
		if start < 0 {
			t.Fatalf("%s has no %q block", name, from)
		}
		rest := sheet[start:]
		end := strings.Index(rest, "\n}")
		if end < 0 {
			t.Fatalf("%s: the %q block is not closed", name, from)
		}
		return rest[:end]
	}
	parse := func(text string) map[string]string {
		found := map[string]string{}
		for _, m := range tokenPattern.FindAllStringSubmatch(text, -1) {
			found[m[1]] = strings.ToLower(m[2])
		}
		return found
	}
	light := parse(block(":root {"))
	if len(light) < 14 {
		t.Fatalf("%s: only %d colour tokens were found", name, len(light))
	}
	dark := map[string]string{}
	for k, v := range light {
		dark[k] = v
	}
	system := parse(block("@media screen and (prefers-color-scheme: dark)"))
	chosen := parse(block(`:root[data-theme="dark"] {`))
	if len(system) < 14 || !equalTokens(system, chosen) {
		t.Fatalf("%s: the system dark and the chosen dark must set the same tokens", name)
	}
	for k, v := range system {
		dark[k] = v
	}
	return map[string]map[string]string{"light": light, "dark": dark}
}

func equalTokens(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestTheTypefaceIsTheOneChosenAndCarriesItsLicence(t *testing.T) {
	font := repositoryFile(t, "cmd", "rootwelld", "auth", "schibsted-grotesk.woff2")
	if sum := sha256.Sum256([]byte(font)); hex.EncodeToString(sum[:]) != fontSHA256 {
		t.Errorf("the typeface is not the file that was chosen: sha256 %x", sum)
	}
	licence := repositoryFile(t, "docs", "third-party", "schibsted-grotesk-LICENSE.txt")
	for _, want := range []string{"SIL OPEN FONT LICENSE Version 1.1", "Copyright 2023 The Schibsted-Grotesk Project Authors"} {
		if !strings.Contains(licence, want) {
			t.Errorf("the typeface's licence does not say %q", want)
		}
	}
	// One face, from this server; no sheet loads anything else.
	for name, sheet := range designSheets(t) {
		for _, u := range regexp.MustCompile(`url\(([^)]*)\)`).FindAllStringSubmatch(sheet, -1) {
			if (name != "style.css" && name != "auth.css") || u[1] != `"/schibsted-grotesk.woff2"` {
				t.Errorf("%s loads %s; only style.css and auth.css may load the typeface, from this server", name, u[1])
			}
		}
		if strings.Contains(sheet, "@import") {
			t.Errorf("%s imports another stylesheet", name)
		}
	}
}

// The sign-in sheet repeats the workspace tokens because the workspace sheet is
// served only after sign-in; the two must never drift apart.
func TestTheSignInSheetUsesTheWorkspaceColours(t *testing.T) {
	sheets := designSheets(t)
	workspace := schemes(t, "style.css", sheets["style.css"])
	signin := schemes(t, "auth.css", sheets["auth.css"])
	for _, scheme := range []string{"light", "dark"} {
		for token, value := range signin[scheme] {
			if workspace[scheme][token] != value {
				t.Errorf("%s: auth.css --%s is %s, style.css has %s", scheme, token, value, workspace[scheme][token])
			}
		}
	}
}

func TestEveryColourTextIsSetInIsLegible(t *testing.T) {
	sheets := designSheets(t)
	tables := schemes(t, "style.css", sheets["style.css"])
	used := map[string]bool{}
	for _, sheet := range sheets {
		for _, m := range textColourPattern.FindAllStringSubmatch(sheet, -1) {
			used[m[1]] = true
		}
	}
	if len(used) < 8 {
		t.Fatalf("only %d text colours were found, which is too few to be right", len(used))
	}
	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		for token := range used {
			value, ok := tokens[token]
			if !ok {
				t.Errorf("%s: text is set in --%s, which is not defined", scheme, token)
				continue
			}
			if token == "rule" || token == "edge" {
				t.Errorf("text is set in --%s, a line colour", token)
				continue
			}
			// The one inversion: a busy button prints the paper on soft ink.
			if token == "paper" {
				if got := contrastRatio(t, value, tokens["ink-soft"]); got < readableContrast {
					t.Errorf("%s: --paper on --ink-soft is %.2f:1", scheme, got)
				}
				continue
			}
			for _, surface := range []string{"paper", "paper-sunk", "card"} {
				if got := contrastRatio(t, value, tokens[surface]); got < readableContrast {
					t.Errorf("%s: --%s (%s) on --%s (%s) is %.2f:1, below %.1f:1", scheme, token, value, surface, tokens[surface], got, readableContrast)
				}
			}
		}
		// Button labels are white on the accent, resting and hovered.
		for _, face := range []string{"accent", "accent-hover"} {
			if got := contrastRatio(t, "#ffffff", tokens[face]); got < readableContrast {
				t.Errorf("%s: white on --%s is %.2f:1", scheme, face, got)
			}
		}
	}
}

// Rootwell's colour is not a verdict's: good, close to expiry and broken are
// said in green, amber and red, and no control may look like one of them.
func TestTheToolColourIsNeverAVerdictColour(t *testing.T) {
	sheets := designSheets(t)
	for scheme, tokens := range schemes(t, "style.css", sheets["style.css"]) {
		for _, control := range []string{"tool", "link", "accent", "accent-hover"} {
			for _, verdict := range []string{"strong", "weak", "insecure", "brand"} {
				if tokens[control] == tokens[verdict] {
					t.Errorf("%s: --%s is the same colour as --%s", scheme, control, verdict)
				}
			}
		}
	}
	// The organisation's red marks only the denyfirst credit.
	for name, sheet := range sheets {
		for _, line := range strings.Split(sheet, "\n") {
			if strings.Contains(line, "var(--brand)") && !strings.HasPrefix(strings.TrimSpace(line), ".credit-stop") {
				t.Errorf("%s draws something other than the credit in the brand red: %s", name, strings.TrimSpace(line))
			}
		}
	}
}

// Every page carries the same rail, the wordmark and the shared typeface.
func TestEveryWorkspacePageCarriesTheSharedShell(t *testing.T) {
	pages := map[string]string{
		"Tools":         repositoryFile(t, "web", "workbench", "index.html"),
		"Certificates":  repositoryFile(t, "cmd", "rootwelld", "auth", "inventory.html"),
		"Renewals":      repositoryFile(t, "cmd", "rootwelld", "auth", "acme.html"),
		"Website check": repositoryFile(t, "cmd", "rootwelld", "auth", "website-check.html"),
		"Account":       repositoryFile(t, "cmd", "rootwelld", "auth", "account.html"),
	}
	for current, page := range pages {
		if !strings.Contains(page, `<a class="wordmark" href="/certificates" aria-label="Rootwell, certificates">rootwell<span class="wordmark-stop">.</span></a>`) {
			t.Errorf("%s: the rail does not carry the wordmark", current)
		}
		for _, label := range []string{"Certificates", "Renewals", "Website check", "Tools", "Account"} {
			item := regexp.MustCompile(`<a class="rail-item" href="[^"]+"( aria-current="page")?><svg class="rail-glyph"[^>]*>.*?</svg>` + regexp.QuoteMeta(label) + `</a>`)
			match := item.FindStringSubmatch(page)
			if match == nil {
				t.Errorf("%s: the rail has no %s item", current, label)
				continue
			}
			if (match[1] != "") != (label == current) {
				t.Errorf("%s: the rail marks %s wrongly as the current place", current, label)
			}
		}
		if !strings.Contains(page, `id="theme-toggle"`) || !strings.Contains(page, `id="rail-sign-out"`) {
			t.Errorf("%s: the rail lacks the colour scheme or Sign out", current)
		}
		for _, gone := range []string{"rail-tag", "rail-soon", "Audit log", "Self-host"} {
			if strings.Contains(page, gone) {
				t.Errorf("%s still shows %q", current, gone)
			}
		}
	}
}
