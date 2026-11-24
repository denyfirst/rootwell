package servingstore

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/vault"
)

var start = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func newVault(t *testing.T) (*vault.Store, string) {
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
	return v, dir
}

func generation(t *testing.T, v *vault.Store) uint64 {
	t.Helper()
	var g uint64
	if err := v.View(func(tx *vault.Tx) error {
		var err error
		g, err = tx.Generation()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return g
}

// verifies checks the served certificate the way a browser that trusts the
// authority does.
func verifies(s Serving, name string, at time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(s.Authority)
	_, err := s.Certificate.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func TestTheFirstStartMakesAnAuthorityForThisHostOnly(t *testing.T) {
	v, _ := newVault(t)
	s, made, err := Ensure(v, start)
	if err != nil || !made || len(s.Added) != 0 {
		t.Fatalf("first start: made %v, added %v: %v", made, s.Added, err)
	}
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := verifies(s, name, start); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := verifies(s, "rootwell.example", start); err == nil {
		t.Fatal("the certificate verified for a name it was not made for")
	}
	before := generation(t, v)
	again, made, err := Ensure(v, start.Add(time.Hour))
	if err != nil || made || again.Fingerprint() != s.Fingerprint() || !bytes.Equal(again.Certificate.Leaf.Raw, s.Certificate.Leaf.Raw) {
		t.Fatalf("second start: made %v: %v", made, err)
	}
	if generation(t, v) != before {
		t.Fatal("a start with nothing due wrote to the vault")
	}
}

func TestTheServerCertificateIsReplacedAMonthBeforeItEnds(t *testing.T) {
	v, _ := newVault(t)
	s, _, err := Ensure(v, start)
	if err != nil {
		t.Fatal(err)
	}
	before := generation(t, v)
	if _, changed, err := Renew(v, start.Add(59*24*time.Hour)); err != nil || changed || generation(t, v) != before {
		t.Fatalf("renewed early: %v %v", changed, err)
	}
	later := start.Add(61 * 24 * time.Hour)
	next, changed, err := Renew(v, later)
	if err != nil || !changed || next.Fingerprint() != s.Fingerprint() || bytes.Equal(next.Certificate.Leaf.Raw, s.Certificate.Leaf.Raw) {
		t.Fatalf("renewal: %v %v", changed, err)
	}
	if err := verifies(next, "localhost", later.Add(80*24*time.Hour)); err != nil {
		t.Fatalf("the new certificate: %v", err)
	}
	if reread, _, err := Ensure(v, later); err != nil || !bytes.Equal(reread.Certificate.Leaf.Raw, next.Certificate.Leaf.Raw) {
		t.Fatalf("the new certificate was not kept: %v", err)
	}
}

func TestNewNamesMakeANewAuthority(t *testing.T) {
	v, _ := newVault(t)
	first, _, err := Ensure(v, start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetNames(v, []string{"*.example"}, start); !errors.Is(err, ErrRefused) {
		t.Fatalf("a wildcard name: %v", err)
	}
	if kept, _, _ := Ensure(v, start); kept.Fingerprint() != first.Fingerprint() {
		t.Fatal("a refused name changed the authority")
	}
	s, err := SetNames(v, []string{"Rootwell.LAN.", "192.168.1.5", "localhost"}, start)
	if err != nil || s.Fingerprint() == first.Fingerprint() {
		t.Fatalf("new names: %v", err)
	}
	if len(s.Added) != 2 || s.Added[0] != "rootwell.lan" || s.Added[1] != "192.168.1.5" {
		t.Fatalf("added names: %v", s.Added)
	}
	for _, name := range []string{"rootwell.lan", "192.168.1.5", "localhost"} {
		if err := verifies(s, name, start); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if reread, made, err := Ensure(v, start); err != nil || made || reread.Fingerprint() != s.Fingerprint() {
		t.Fatalf("the new authority was not kept: %v %v", made, err)
	}
}

func TestTheAuthorityKeyIsSealedAndTheRecordReadStrictly(t *testing.T) {
	v, dir := newVault(t)
	if _, _, err := Ensure(v, start); err != nil {
		t.Fatal(err)
	}
	var stored record
	if err := v.View(func(tx *vault.Tx) error {
		var err error
		stored, _, err = read(tx, v)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(func(tx *vault.Tx) error {
		return tx.Put(kind, id(v), []byte(`{"names":[],"authority":"","authority_key":"","certificate":"","key":"","extra":1}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(v, start); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a record with an unknown field: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "rootwell.db"))
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string][]byte{"authority key": stored.AuthorityKey, "server key": stored.Key} {
		if len(secret) == 0 || bytes.Contains(raw, secret[len(secret)-40:]) {
			t.Fatalf("the vault file holds the %s in the clear", name)
		}
	}
}
