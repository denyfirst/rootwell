package acmestaging

import (
	"time"

	"github.com/denyfirst/rootwell/internal/providerretry"
)

// Called only for responses from an already guarded, fixed-provider transport.
// Keep the longest wait and sticky malformed-hint block across the bounded
// distinct-resource operation. No raw header/body/URL escapes this boundary.
func captureOperationWait(prior providerretry.Hint, values []string, status int, at time.Time) providerretry.Hint {
	next := providerretry.RetryAfter(values, at)
	if len(values) == 0 && (status == 429 || status == 503) {
		next.NotBefore = at.Add(5 * time.Minute)
	}
	prior.Blocked = prior.Blocked || next.Blocked
	if next.NotBefore.After(prior.NotBefore) {
		prior.NotBefore = next.NotBefore
	}
	return prior
}

func operationWaitFailure(hint providerretry.Hint) error {
	if hint.NotBefore.IsZero() && !hint.Blocked {
		return errRefused
	}
	return &operationWaitError{hint: hint}
}

type operationWaitError struct{ hint providerretry.Hint }

func (*operationWaitError) Error() string { return "CA operation not confirmed" }
func (*operationWaitError) Unwrap() error { return errRefused }
func (e *operationWaitError) ProviderWait() providerretry.Hint {
	if e == nil {
		return providerretry.Hint{}
	}
	return e.hint
}
