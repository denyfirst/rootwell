package version

import (
	"strings"
	"testing"
)

func TestVersionValue(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		want      string
	}{
		{name: "semantic version", candidate: "v0.1.0", want: "v0.1.0"},
		{name: "prerelease and metadata", candidate: "v0.1.0-rc.1+build_7", want: "v0.1.0-rc.1+build_7"},
		{name: "empty", candidate: "", want: fallback},
		{name: "newline", candidate: "v0.1.0\ninjected", want: fallback},
		{name: "carriage return", candidate: "v0.1.0\rinjected", want: fallback},
		{name: "tab", candidate: "v0.1.0\tinjected", want: fallback},
		{name: "terminal escape", candidate: "v0.1.0\x1b[31m", want: fallback},
		{name: "space", candidate: "v0.1.0 dirty", want: fallback},
		{name: "too long", candidate: strings.Repeat("a", 129), want: fallback},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalize(test.candidate); got != test.want {
				t.Fatalf("normalize(%q) = %q, want %q", test.candidate, got, test.want)
			}
		})
	}
}

func FuzzVersionValue(f *testing.F) {
	f.Add("v0.1.0")
	f.Add("v0.1.0\ninjected")
	f.Add("\x1b[31m")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		got := normalize(input)
		if got == "" || len(got) > 128 {
			t.Fatalf("normalize() returned invalid length %d", len(got))
		}
		for _, r := range got {
			if !isVersionRune(r) {
				t.Fatalf("normalize() returned unsafe rune %q in %q", r, got)
			}
		}
	})
}
