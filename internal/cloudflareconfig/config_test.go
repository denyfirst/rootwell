package cloudflareconfig

import (
	"strings"
	"testing"
)

func TestCloudflareConfigSyntaxDoesNotNormalizeOrAcceptMalformedSecrets(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	token := strings.Repeat("A", 40)
	if !Valid(id, "example.com", []byte(token)) || !Valid(id, "dns.example.com", []byte(strings.Repeat("z", 256))) {
		t.Fatal("valid canonical profile refused")
	}
	for _, tc := range [][3]string{
		{"../path", "example.com", token}, {strings.ToUpper(id), "example.com", token},
		{id, "Example.com", token}, {id, "*.example.com", token}, {id, "example.com.", token},
		{id, "localhost", token}, {id, "https://example.com", token}, {id, "example.internal", token},
		{id, "example.com", "short"}, {id, "example.com", strings.Repeat("A", 257)},
		{id, "example.com", token + "\r\n"}, {id, "example.com", token + "="}, {id, "example.com", token + " "},
	} {
		if Valid(tc[0], tc[1], []byte(tc[2])) {
			t.Fatal("invalid profile accepted")
		}
	}
}
