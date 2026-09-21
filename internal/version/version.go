// Package version validates build version metadata before it is displayed.
package version

const fallback = "development"

// value may be replaced at link time with:
//
// -X github.com/denyfirst/rootwell/internal/version.value=v1.2.3
var value = fallback

// Value returns safe, single-line build metadata.
func Value() string {
	return normalize(value)
}

func normalize(candidate string) string {
	if candidate == "" || len(candidate) > 128 {
		return fallback
	}

	for _, r := range candidate {
		if !isVersionRune(r) {
			return fallback
		}
	}

	return candidate
}

func isVersionRune(r rune) bool {
	return r >= 'a' && r <= 'z' ||
		r >= 'A' && r <= 'Z' ||
		r >= '0' && r <= '9' ||
		r == '.' || r == '-' || r == '+' || r == '_'
}
