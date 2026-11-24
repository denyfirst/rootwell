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

// The ratio text needs at the sizes these pages use, and the ratio a mark that
// is not text needs (WCAG 2.2, 1.4.3 and 1.4.11).
const (
	readableContrast = 4.5
	markContrast     = 3.0
)

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

// The one stylesheet every page uses.
func sharedSheet(t *testing.T) string {
	return repositoryFile(t, "web", "workbench", "rootwell.css")
}

// The seven pages in the menu.
func menuPages(t *testing.T) map[string]string {
	return map[string]string{
		"Certificates":  repositoryFile(t, "web", "workbench", "certificates.html"),
		"Website check": repositoryFile(t, "cmd", "rootwelld", "auth", "website-check.html"),
		"Inspect":       repositoryFile(t, "web", "workbench", "inspect.html"),
		"Convert":       repositoryFile(t, "web", "workbench", "convert.html"),
		"Request":       repositoryFile(t, "web", "workbench", "request.html"),
		"Account":       repositoryFile(t, "cmd", "rootwelld", "auth", "account.html"),
		"Installation":  repositoryFile(t, "cmd", "rootwelld", "auth", "installation.html"),
	}
}

// The menu pages, and the sign-in and setup pages that come before them.
func designedPages(t *testing.T) map[string]string {
	pages := menuPages(t)
	pages["Sign in"] = repositoryFile(t, "cmd", "rootwelld", "auth", "login.html")
	pages["Setup"] = repositoryFile(t, "cmd", "rootwelld", "auth", "setup.html")
	return pages
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
	// One face, from this server, and one sheet that loads nothing else.
	for _, dir := range [][]string{{"web", "workbench"}, {"cmd", "rootwelld", "auth"}} {
		sheets, _ := filepath.Glob(filepath.Join(append([]string{"..", ".."}, append(dir, "*.css")...)...))
		for _, sheet := range sheets {
			if filepath.Base(sheet) != "rootwell.css" {
				t.Errorf("%s is a second stylesheet; every page wears rootwell.css", sheet)
			}
		}
	}
	sheets := map[string]string{"rootwell.css": sharedSheet(t)}
	for name, sheet := range sheets {
		for _, u := range regexp.MustCompile(`url\(([^)]*)\)`).FindAllStringSubmatch(sheet, -1) {
			if name != "rootwell.css" || u[1] != `"/schibsted-grotesk.woff2"` {
				t.Errorf("%s loads %s; only the typeface may be loaded, from this server", name, u[1])
			}
		}
		if strings.Contains(sheet, "@import") {
			t.Errorf("%s imports another stylesheet", name)
		}
	}
}

// Rootwell is graphite: a near-black control in light, a near-white one in
// dark, and a grey full stop after the wordmark. Its label must read on it.
func TestRootwellIsGraphiteAndItsControlsAreLegible(t *testing.T) {
	tables := schemes(t, "rootwell.css", sharedSheet(t))
	for scheme, want := range map[string]map[string]string{
		"light": {"accent": "#1f2329", "accent-hover": "#3a3f47", "on-accent": "#ffffff", "stop": "#7a828e"},
		"dark":  {"accent": "#eceef1", "on-accent": "#16181d"},
	} {
		for token, value := range want {
			if got := tables[scheme][token]; got != value {
				t.Errorf("%s: --%s is %s, the graphite design has %s", scheme, token, got, value)
			}
		}
	}
	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		for _, face := range []string{"accent", "accent-hover"} {
			if got := contrastRatio(t, tokens["on-accent"], tokens[face]); got < readableContrast {
				t.Errorf("%s: --on-accent on --%s is %.2f:1, below %.1f:1", scheme, face, got, readableContrast)
			}
		}
	}
}

func TestEveryColourTextIsSetInIsLegible(t *testing.T) {
	sheet := sharedSheet(t)
	tables := schemes(t, "rootwell.css", sheet)
	used := map[string]bool{}
	for _, m := range textColourPattern.FindAllStringSubmatch(sheet, -1) {
		used[m[1]] = true
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
			switch token {
			case "rule", "rule-strong":
				t.Errorf("text is set in --%s, a line colour", token)
			case "on-accent":
				// Checked on the accent by TestRootwellIsGraphiteAndItsControlsAreLegible.
			case "paper":
				// The one inversion: a disabled button prints the paper on faint ink.
				if got := contrastRatio(t, value, tokens["ink-faint"]); got < readableContrast {
					t.Errorf("%s: --paper on --ink-faint is %.2f:1", scheme, got)
				}
			case "stop":
				// The wordmark's full stop is a mark, not text.
				for _, surface := range []string{"paper", "paper-sunk", "card"} {
					if got := contrastRatio(t, value, tokens[surface]); got < markContrast {
						t.Errorf("%s: --stop on --%s is %.2f:1, below %.1f:1", scheme, surface, got, markContrast)
					}
				}
			default:
				for _, surface := range []string{"paper", "paper-sunk", "card"} {
					if got := contrastRatio(t, value, tokens[surface]); got < readableContrast {
						t.Errorf("%s: --%s (%s) on --%s (%s) is %.2f:1, below %.1f:1", scheme, token, value, surface, tokens[surface], got, readableContrast)
					}
				}
			}
		}
	}
}

// The lifetime bar's track is the certificate's whole life. A certificate
// issued today has no filled part yet, so on a card or the side sheet the track
// alone shows the bar; it must stand apart from the card in both schemes.
func TestTheLifetimeTrackShowsOnACard(t *testing.T) {
	sheet := sharedSheet(t)
	m := regexp.MustCompile(`(?m)^\.lifetime-bar \{[^}]*background: var\(--([a-z-]+)\)`).FindStringSubmatch(sheet)
	if m == nil {
		t.Fatal(".lifetime-bar no longer sets its track with a colour token")
	}
	const trackContrast = 1.3
	for scheme, tokens := range schemes(t, "rootwell.css", sheet) {
		if got := contrastRatio(t, tokens[m[1]], tokens["card"]); got < trackContrast {
			t.Errorf("%s: the lifetime track --%s on --card is %.2f:1, below %.1f:1", scheme, m[1], got, trackContrast)
		}
	}
}

// Rootwell's colour is not a verdict's: good, close to expiry and broken are
// said in green, amber and red, and no control may look like one of them.
func TestTheToolColourIsNeverAVerdictColour(t *testing.T) {
	sheet := sharedSheet(t)
	for scheme, tokens := range schemes(t, "rootwell.css", sheet) {
		for _, control := range []string{"tool", "link", "accent", "accent-hover", "stop"} {
			for _, verdict := range []string{"strong", "weak", "insecure", "brand"} {
				if tokens[control] == tokens[verdict] {
					t.Errorf("%s: --%s is the same colour as --%s", scheme, control, verdict)
				}
			}
		}
	}
	// The organisation's red marks only the denyfirst credit.
	for _, line := range strings.Split(sheet, "\n") {
		if strings.Contains(line, "var(--brand)") && !strings.HasPrefix(strings.TrimSpace(line), ".credit-stop") {
			t.Errorf("rootwell.css draws something other than the credit in the brand red: %s", strings.TrimSpace(line))
		}
	}
}

// Every page in the menu carries the same rail: the wordmark, the seven pages
// with the current one marked, the colour scheme, Sign out and the credit.
func TestEveryWorkspacePageCarriesTheSharedShell(t *testing.T) {
	paths := map[string]string{"Certificates": "/certificates", "Website check": "/website-check", "Inspect": "/inspect",
		"Convert": "/convert", "Request": "/request", "Account": "/account", "Installation": "/installation"}
	for current, page := range menuPages(t) {
		if !strings.Contains(page, `<a class="wordmark" href="/certificates" aria-label="Rootwell, certificates">rootwell<span class="wordmark-stop">.</span></a>`) {
			t.Errorf("%s: the rail does not carry the wordmark", current)
		}
		for label, path := range paths {
			item := regexp.MustCompile(`<a class="nav-item" href="` + regexp.QuoteMeta(path) + `"( aria-current="page")?><svg class="icon"[^>]*>.*?</svg>` + regexp.QuoteMeta(label) + `</a>`)
			match := item.FindStringSubmatch(page)
			if match == nil {
				t.Errorf("%s: the rail has no %s item", current, label)
				continue
			}
			if (match[1] != "") != (label == current) {
				t.Errorf("%s: the rail marks %s wrongly as the current place", current, label)
			}
		}
		if strings.Count(page, `aria-current="page"`) != 1 {
			t.Errorf("%s: the rail marks more or fewer than one current place", current)
		}
		for _, part := range []string{`id="theme-toggle"`, `id="rail-sign-out"`, `<p class="credit">rootwell, by denyfirst<span class="credit-stop">.</span></p>`} {
			if !strings.Contains(page, part) {
				t.Errorf("%s: the rail lacks %s", current, part)
			}
		}
		for _, gone := range []string{"Renewals", "Tools", "rail-tag", "rail-soon", "Audit log", "Self-host"} {
			if strings.Contains(page, gone) {
				t.Errorf("%s still shows %q", current, gone)
			}
		}
	}
}

// Every page, sign-in and setup included, draws with the shared sheet alone
// and carries no style of its own.
func TestEveryPageWearsTheSharedSheetAndNoInlineStyle(t *testing.T) {
	stylesheet := regexp.MustCompile(`<link rel="stylesheet"[^>]*>`)
	for name, page := range designedPages(t) {
		if got := stylesheet.FindAllString(page, -1); len(got) != 1 || got[0] != `<link rel="stylesheet" href="/rootwell.css">` {
			t.Errorf("%s: stylesheets %q, want only /rootwell.css", name, got)
		}
		if regexp.MustCompile(`(?i)\sstyle\s*=`).MatchString(page) || strings.Contains(page, "<style") {
			t.Errorf("%s carries an inline style", name)
		}
		if !strings.Contains(page, `<script src="/theme.js"></script>`) || !strings.Contains(page, `<link rel="icon" href="/favicon.svg" type="image/svg+xml">`) {
			t.Errorf("%s lacks the colour scheme script or the icon", name)
		}
	}
}
