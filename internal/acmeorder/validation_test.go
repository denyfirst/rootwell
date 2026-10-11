package acmeorder

import "testing"

func TestValidationVerdictRequiresReadyAndEveryAuthorization(t *testing.T) {
	names := []string{"*.example.com", "example.com"}
	for _, tc := range []struct {
		order    string
		statuses []string
		want     string
	}{
		{"ready", []string{"valid", "valid"}, "domain-verified"},
		{"pending", []string{"valid", "valid"}, "validation-waiting"},
		{"ready", []string{"valid", "pending"}, ""},
		{"pending", []string{"valid", "pending"}, "validation-waiting"},
		{"invalid", []string{"valid", "valid"}, "validation-failed"},
		{"pending", []string{"invalid", "pending"}, "validation-failed"},
		{"pending", []string{"valid"}, ""},
		{"valid", []string{"valid", "valid"}, ""},
		{"ready", []string{"VALID", "valid"}, ""},
	} {
		if ValidationState(Validation{Expires: "2030-01-01T00:00:00Z", OrderStatus: tc.order, Statuses: tc.statuses}, names) != tc.want {
			t.Fatal("unsupported/partial truth accepted")
		}
	}
}
