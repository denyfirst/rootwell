package watchstore

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/vault"
)

func newStore(t *testing.T) (*Store, *vault.Store) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the vault opens only in a private Linux directory")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := vault.NewInstanceKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return New(v), v
}

func TestSitesAreAddedOnceAndUpToTheLimit(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Add("shop.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("shop.example"); !errors.Is(err, ErrWatched) {
		t.Fatalf("a site watched twice: %v", err)
	}
	for i := 1; i < MaxSites; i++ {
		if _, err := s.Add(fmt.Sprintf("site%d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Add("one-more.example"); !errors.Is(err, ErrFull) {
		t.Fatalf("site %d: %v", MaxSites+1, err)
	}
	if err := s.Remove("shop.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("shop.example"); !errors.Is(err, ErrNotWatched) {
		t.Fatalf("removed twice: %v", err)
	}
	sites, err := s.List()
	if err != nil || len(sites) != MaxSites-1 || sites[0].Target != "site1.example" {
		t.Fatalf("list: %d %v", len(sites), err)
	}
}

func TestASiteIsDueEverySixHours(t *testing.T) {
	s, _ := newStore(t)
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	for _, target := range []string{"a.example", "b.example"} {
		if _, err := s.Add(target); err != nil {
			t.Fatal(err)
		}
	}
	if due, _ := s.Due(now); len(due) != 2 {
		t.Fatalf("new sites are due at once: %d", len(due))
	}
	if _, err := s.Record("a.example", Result{State: "verified", Leaf: "AA", LeafName: "a.example", NotAfter: "2027-01-01T00:00:00Z"}, now); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.Due(now.Add(6*time.Hour - time.Minute)); len(due) != 1 || due[0].Target != "b.example" {
		t.Fatalf("checked under six hours ago: %+v", due)
	}
	if due, _ := s.Due(now.Add(6 * time.Hour)); len(due) != 2 || due[0].Target != "b.example" {
		t.Fatalf("the longest waiting first: %+v", due)
	}
}

func TestEachChangeIsToldOnce(t *testing.T) {
	s, _ := newStore(t)
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	if _, err := s.Add("shop.example"); err != nil {
		t.Fatal(err)
	}
	good := Result{State: "verified", Leaf: "AA", LeafName: "shop.example", NotAfter: "2027-01-01T00:00:00Z"}
	steps := []struct {
		result  Result
		newCert bool
		problem bool
		quiet   bool
	}{
		// The first check tells nothing, even a problem: the person just saw it.
		{Result{State: "attention", Problem: "Expires soon", Leaf: "AA", LeafName: "shop.example", NotAfter: "2027-01-01T00:00:00Z"}, false, false, true},
		{good, false, false, true},
		{good, false, false, true},
		// Unreachable: told once, with the certificate last seen kept.
		{Result{State: "unreachable", Problem: "Nothing answers on port 443."}, false, true, false},
		{Result{State: "unreachable", Problem: "Nothing answers on port 443."}, false, false, true},
		{good, false, false, true},
		// Renewed and installed: told once.
		{Result{State: "verified", Leaf: "BB", LeafName: "shop.example", NotAfter: "2027-06-01T00:00:00Z"}, true, false, false},
		{Result{State: "verified", Leaf: "BB", LeafName: "shop.example", NotAfter: "2027-06-01T00:00:00Z"}, false, false, true},
		// A broken chain on the same certificate: told once, then quiet.
		{Result{State: "failed", Problem: "The chain is incomplete", Leaf: "BB", LeafName: "shop.example", NotAfter: "2027-06-01T00:00:00Z"}, false, true, false},
		{Result{State: "failed", Problem: "The chain is incomplete", Leaf: "BB", LeafName: "shop.example", NotAfter: "2027-06-01T00:00:00Z"}, false, false, true},
	}
	for i, step := range steps {
		now = now.Add(Every)
		change, err := s.Record("shop.example", step.result, now)
		if err != nil {
			t.Fatal(err)
		}
		if step.quiet {
			if change != nil {
				t.Fatalf("step %d told %+v", i, change)
			}
			continue
		}
		if change == nil || change.NewCertificate != step.newCert || change.NewProblem != step.problem {
			t.Fatalf("step %d: %+v", i, change)
		}
		if step.newCert && change.PreviousEnd != "2027-01-01T00:00:00Z" {
			t.Fatalf("step %d: the previous end: %+v", i, change)
		}
	}
	sites, _ := s.List()
	if sites[0].Leaf != "BB" || sites[0].State != "failed" || sites[0].Since == "" || sites[0].Problem != "The chain is incomplete" {
		t.Fatalf("the site reads %+v", sites[0])
	}
	// A site removed while it was checked stays removed.
	if err := s.Remove("shop.example"); err != nil {
		t.Fatal(err)
	}
	if change, err := s.Record("shop.example", good, now); err != nil || change != nil {
		t.Fatalf("a removed site was recorded: %+v %v", change, err)
	}
	if sites, _ := s.List(); len(sites) != 0 {
		t.Fatal("a removed site came back")
	}
}

func TestASiteRecordIsReadStrictly(t *testing.T) {
	s, v := newStore(t)
	if _, err := s.Add("shop.example"); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(func(t *vault.Tx) error {
		return t.Put(kind, v.Index(kind, "other.example"), []byte(`{"target":"shop.example","added_at":"2026-11-27T09:00:00Z"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a record under another site's index was listed: %v", err)
	}
}
