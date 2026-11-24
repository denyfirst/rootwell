package main

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The gate serves rootwell.wasm only to a ready session, and wasm-loader.js
// fetches it. A browser sends the session cookie only when the fetch's
// credentials mode allows it, so the two must agree, or every page that needs
// the engine (Certificates' Add dialog, Inspect, Convert, Request) loses it on
// a real installation while tests with stand-in servers still pass.
func TestEngineLoaderSendsTheSessionTheGateRequires(t *testing.T) {
	loader, err := os.ReadFile(filepath.Join("..", "..", "web", "workbench", "wasm-loader.js"))
	if err != nil {
		t.Fatal(err)
	}
	options := regexp.MustCompile(`fetch\("rootwell\.wasm",\s*\{([^}]*)\}`).FindSubmatch(loader)
	if options == nil {
		t.Fatal("wasm-loader.js no longer fetches rootwell.wasm with an options object")
	}
	mode := "same-origin" // the Fetch standard's default
	if m := regexp.MustCompile(`credentials:\s*"([a-z-]+)"`).FindSubmatch(options[1]); m != nil {
		mode = string(m[1])
	}
	if !regexp.MustCompile(`redirect:\s*"error"`).Match(options[1]) {
		t.Fatal(`the engine fetch must keep redirect: "error", so a sign-in redirect fails instead of feeding HTML to WebAssembly`)
	}

	g, cookie, _ := readyGate(t)
	var sent *http.Cookie
	switch mode {
	case "same-origin", "include":
		sent = cookie
	case "omit":
	default:
		t.Fatalf("unknown credentials mode %q", mode)
	}
	w := call(g, "GET", "/rootwell.wasm", "", sent)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/wasm" {
		t.Fatalf("the engine fetch (credentials %q) gets %d %q from the gate, so pages would have no engine", mode, w.Code, w.Header().Get("Location"))
	}
}
