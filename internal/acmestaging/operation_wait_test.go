package acmestaging

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func TestCAOperationWaitBoundedStickyAndSecretFree(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	hint := captureOperationWait(providerretry.Hint{}, []string{"600"}, 200, at)
	hint = captureOperationWait(hint, []string{"10"}, 200, at.Add(time.Second))
	if hint.Blocked || !hint.NotBefore.Equal(at.Add(10*time.Minute)) {
		t.Fatal("short response reset longer wait")
	}
	for _, values := range [][]string{{"1", "2"}, {"untrusted-secret-sentinel"}, {"99999999999999999"}, {"604801"}} {
		blocked := captureOperationWait(hint, values, 200, at)
		blocked = captureOperationWait(blocked, []string{"1"}, 200, at)
		if !blocked.Blocked || blocked.NotBefore.Before(hint.NotBefore) {
			t.Fatal("invalid hint unblocked or shortened")
		}
		err := operationWaitFailure(blocked)
		var report interface{ ProviderWait() providerretry.Hint }
		if !errors.Is(err, errRefused) || !errors.As(err, &report) || !report.ProviderWait().Blocked || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("failure lost wait or reflected provider data")
		}
	}
	for _, status := range []int{429, 503} {
		if got := captureOperationWait(providerretry.Hint{}, nil, status, at); got.Blocked || !got.NotBefore.Equal(at.Add(5*time.Minute)) {
			t.Fatal("rate/service response has no minimum hold")
		}
	}
	for _, v := range []any{acmeorder.Instructions{Wait: hint}, acmeorder.Validation{Wait: hint}, CertificateObservation{Wait: hint}} {
		body, err := json.Marshal(v)
		if err != nil || strings.Contains(string(body), "Wait") || strings.Contains(string(body), "NotBefore") {
			t.Fatal("transient protocol metadata became public/stored JSON")
		}
	}
}

func TestCAOrderCarriesOnlyBoundedWaitAndNeverRetriesFailure(t *testing.T) {
	key := testAccountSigner(t)
	before := time.Now().UTC()
	deps, calls := orderServer(t, key, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "600"); goodOrder(w, r) }, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "10"); goodAuth(w, r) })
	info, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, "", testOrderNames, func(string) error { return nil })
	if err != nil || info.Wait.Blocked || info.Wait.NotBefore.Before(before.Add(10*time.Minute)) || calls.posts.Load() != 1 || calls.authz.Load() != 2 {
		t.Fatal("successful CA operation dropped wait or retried", err)
	}
	deps, calls = orderServer(t, key, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(429)
	}, goodAuth)
	info, err = dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, "", testOrderNames, func(string) error { t.Fatal("failed order minted checkpoint"); return nil })
	var report interface{ ProviderWait() providerretry.Hint }
	if !errors.Is(err, errRefused) || !errors.As(err, &report) || report.ProviderWait().NotBefore.Before(before.Add(time.Hour)) || info.URL != "" || len(info.Records) != 0 || info.Wait != (providerretry.Hint{}) || calls.posts.Load() != 1 || calls.authz.Load() != 0 {
		t.Fatal("CA failure lost wait, retried or returned partial result")
	}
}

func TestCACertificateProcessingCarriesWaitWithoutPolling(t *testing.T) {
	private, csr, _, public := certificateFixture(t)
	before := time.Now().UTC()
	result, calls, err := runCertificate(t, private, csr, public, true, "processing", "processing", func(kind string, w http.ResponseWriter, _ *http.Request) bool {
		if kind == "order" {
			w.Header().Set("Retry-After", "900")
		}
		return false
	})
	if err != nil || result.State != "processing" || result.Wait.Blocked || result.Wait.NotBefore.Before(before.Add(15*time.Minute)) || calls.order.Load() != 1 || calls.finalize.Load() != 0 || calls.cert.Load() != 0 {
		t.Fatal("certificate read lost wait or polled/finalized", err)
	}
}

func TestCAValidationReadCarriesWaitWithoutAcceptingChallenges(t *testing.T) {
	key := testAccountSigner(t)
	before := time.Now().UTC()
	deps, calls := orderServer(t, key, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "600"); goodOrder(w, r) }, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, validationAuth(strings.HasSuffix(r.URL.Path, "101"), "pending"))
	})
	result, err := dnsValidation(context.Background(), func() bool { return true }, deps, key, testAccountURL, validationSaved(t, key), testOrderNames, true)
	if err != nil || acmeorder.ValidationState(result, testOrderNames) != "validation-waiting" || result.Wait.Blocked || result.Wait.NotBefore.Before(before.Add(10*time.Minute)) || calls.posts.Load() != 1 || calls.authz.Load() != 2 {
		t.Fatal("read-only validation lost wait or repeated work", err)
	}
}
