package acmeorder

// Validation is a bounded CA observation, not certificate issuance authority.
// Statuses follow the exact canonical Names order, never provider response order.
type Validation struct {
	URL         string   `json:"url"`
	Expires     string   `json:"expires"`
	OrderStatus string   `json:"order_status"`
	Statuses    []string `json:"statuses"`
}

func ValidationState(v Validation, names []string) string {
	if !CanonicalNames(names) || !Time(v.Expires) || len(v.Statuses) != len(names) {
		return ""
	}
	if v.OrderStatus != "pending" && v.OrderStatus != "ready" && v.OrderStatus != "invalid" {
		return ""
	}
	allValid, failed := true, v.OrderStatus == "invalid"
	for _, status := range v.Statuses {
		switch status {
		case "valid":
		case "pending":
			allValid = false
		case "invalid", "expired", "revoked", "deactivated":
			allValid = false
			failed = true
		default:
			return ""
		}
	}
	if failed {
		return "validation-failed"
	}
	if allValid && v.OrderStatus == "ready" {
		return "domain-verified"
	}
	// A ready order with a pending authorization is inconsistent, not success.
	if v.OrderStatus == "ready" {
		return ""
	}
	return "validation-waiting"
}

func ValidationStarted(state string) bool {
	return state == "validation-pending" || state == "validation-waiting" || state == "validation-failed" || state == "domain-verified"
}
