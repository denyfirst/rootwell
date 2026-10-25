package renewalpolicy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

var clock = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

const information = `{"suggestedWindow":{"start":"2026-10-27T12:00:00Z","end":"2026-10-28T12:00:00Z"}}`

func TestARIInformationStrictBoundsCanonicalMeaningAndNoURLAuthority(t *testing.T) {
	input := []byte(information[:len(information)-1] + `,"explanationURL":"https://private-error-sentinel.invalid/never-fetch","future":{"nested":[true,1,"ignored"]}}`)
	before := bytes.Clone(input)
	i, err := ParseInformation(input, []string{"21600"}, clock)
	if err != nil || i.Window.Start != clock.Add(24*time.Hour) || i.Window.End != clock.Add(48*time.Hour) || i.CheckedAt != clock || i.CheckAfter != clock.Add(6*time.Hour) || !bytes.Equal(before, input) {
		t.Fatal("legitimate ARI response refused/changed", err)
	}
	// Offsets/fractions preserve the RFC3339 instant, not local clock text.
	shifted := strings.ReplaceAll(information, "12:00:00Z", "14:00:00.123+02:00")
	i, err = ParseInformation([]byte(shifted), []string{"60"}, clock)
	if err != nil || !i.Window.Start.Equal(clock.Add(24*time.Hour+123*time.Millisecond)) {
		t.Fatal("RFC3339 offset/fraction lost", err)
	}
	for _, body := range []string{
		"", "null", "[]", information + "{}", string([]byte{0xff}), strings.Repeat(" ", MaxInformationBytes+1),
		`{"suggestedWindow":null}`, `{"suggestedWindow":{"start":null,"end":"2026-10-28T12:00:00Z"}}`,
		strings.Replace(information, "suggestedWindow", "SuggestedWindow", 1),
		strings.Replace(information, `"start":`, `"Start":`, 1),
		strings.Replace(information, `"start":`, `"start":"2026-10-27T12:00:00Z","start":`, 1),
		information[:len(information)-1] + `,"suggested\u0057indow":{}}`,
		information[:len(information)-1] + `,"other":{"duplicate":1,"duplicate":2}}`,
		strings.Replace(information, "2026-10-28", "2026-10-27", 1),
		strings.Replace(information, "2026-10-28", "2026-10-26", 1),
		strings.Replace(information, "2026-10-28", "2026-02-30", 1),
		strings.Replace(information, "2026-10-28", "2101-10-28", 1),
		strings.Replace(information, "12:00:00Z", "12:00:00,123Z", 1),
		strings.Replace(information, "12:00:00Z", "12:00:00+24:00", 1),
		strings.Replace(information, "12:00:00Z", "12:00:00.1234567891Z", 1),
		information[:len(information)-1] + `,"explanationURL":null}`,
		information[:len(information)-1] + `,"explanationURL":"` + strings.Repeat("x", 2049) + `"}`,
		information[:len(information)-1] + `,"future":` + strings.Repeat("[", 9) + `0` + strings.Repeat("]", 9) + `}`,
		information[:len(information)-1] + `,"future":[` + strings.Repeat("0,", 256) + `0]}`,
	} {
		out, err := ParseInformation([]byte(body), []string{"60"}, clock)
		if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(out, Information{}) || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("malformed response escaped or partial result", body)
		}
	}
	if _, err := ParseInformation([]byte(information), nil, clock); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing Retry-After trusted")
	}
}

func TestARIRetryAfterBoundsAndErrorPolicy(t *testing.T) {
	for _, tc := range []struct {
		values []string
		delay  time.Duration
	}{
		{[]string{"0"}, time.Minute}, {[]string{"1"}, time.Minute}, {[]string{"60"}, time.Minute}, {[]string{"21600"}, 6 * time.Hour}, {[]string{"86400"}, 24 * time.Hour}, {[]string{strings.Repeat("9", 64)}, 24 * time.Hour},
		{[]string{clock.Add(-time.Hour).Format("Mon, 02 Jan 2006 15:04:05 GMT")}, time.Minute},
		{[]string{clock.Add(48 * time.Hour).Format("Mon, 02 Jan 2006 15:04:05 GMT")}, 24 * time.Hour},
	} {
		next, err := NextCheck(tc.values, clock)
		if err != nil || !next.Equal(clock.Add(tc.delay)) {
			t.Fatal("valid ARI interval refused/wrong", tc.values, err, next)
		}
	}
	for _, values := range [][]string{nil, {}, {""}, {"1", "2"}, {"+60"}, {"-1"}, {" 60"}, {"60 "}, {"1.0"}, {"1e3"}, {strings.Repeat("9", 65)}, {"Tue, 26 Oct 2026 12:00:00 GMT"}, {"https://error-sentinel.invalid"}} {
		next, err := NextCheck(values, clock)
		if !errors.Is(err, ErrInvalid) || !next.IsZero() {
			t.Fatal("bad Retry-After trusted", values)
		}
	}
	for n := 1; n <= 6; n++ {
		for _, temporary := range []bool{false, true} {
			want := 6 * time.Hour
			if temporary && n < 6 {
				want = time.Minute * time.Duration(1<<(n-1))
			}
			next, err := ErrorCheckAt(clock, temporary, n)
			if err != nil || !next.Equal(clock.Add(want)) {
				t.Fatal("error delay lost bound", n, temporary)
			}
		}
	}
	for _, n := range []int{-1, 0, 7} {
		if next, err := ErrorCheckAt(clock, true, n); err == nil || !next.IsZero() {
			t.Fatal("unbounded error counter")
		}
	}
}

func TestARISelectionRandomWindowBackoffAndFallback(t *testing.T) {
	life := Window{clock.Add(-time.Hour), clock.Add(90*24*time.Hour - time.Hour)}
	info, err := ParseInformation([]byte(information), []string{"21600"}, clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, last := range []bool{false, true} {
		pick := func(bound *big.Int) (*big.Int, error) {
			if last {
				return new(big.Int).Sub(bound, big.NewInt(1)), nil
			}
			return big.NewInt(0), nil
		}
		s, err := selectAt(life, &info, clock, time.Time{}, pick)
		if err != nil || s.Source != "ari" || s.At.Before(info.Window.Start) || !s.At.Before(info.Window.End) || !last && !s.At.Equal(info.Window.Start) || last && !s.At.Equal(info.Window.End.Add(-time.Nanosecond)) {
			t.Fatal("selected outside exact half-open CA window", err, s)
		}
	}
	past := info
	past.Window = Window{clock.Add(-time.Hour), clock.Add(-time.Minute)}
	backoff := clock.Add(3 * time.Hour)
	for _, next := range []time.Time{{}, backoff} {
		s, err := selectAt(life, &past, clock, next, func(*big.Int) (*big.Int, error) { return big.NewInt(0), nil })
		want := clock
		if !next.IsZero() {
			want = next
		}
		if err != nil || s.At != want {
			t.Fatal("urgent ARI bypassed backoff", err, s)
		}
	}
	for _, days := range []int{1, 9, 10, 90, 400} {
		span := time.Duration(days) * 24 * time.Hour
		life := Window{clock, clock.Add(span)}
		w, err := FallbackWindow(life)
		if err != nil || !w.Start.Before(w.End) || !w.Start.After(life.Start) {
			t.Fatal("bad fallback")
		}
		end := clock.Add(span / 3 * 2)
		if days < 10 {
			end = clock.Add(span / 2)
		}
		if !w.End.Equal(end) || w.Start != end.Add(-span/24) {
			t.Fatal("hard-coded validity or wrong short-life backstop")
		}
		s, err := Select(life, nil, clock, time.Time{})
		if err != nil || s.Source != "fallback" || s.At.Before(w.Start) || !s.At.Before(w.End) {
			t.Fatal("real random fallback failed", err)
		}
	}
	for _, tc := range []struct {
		info     *Information
		at, wait time.Time
		pick     func(*big.Int) (*big.Int, error)
	}{
		{&info, life.End, time.Time{}, nil}, {&info, clock, life.End, nil},
		{&Information{Window: info.Window, CheckedAt: clock.Add(time.Second), CheckAfter: clock.Add(time.Hour)}, clock, time.Time{}, nil},
		{&Information{Window: info.Window, CheckedAt: clock.Add(-time.Hour), CheckAfter: clock}, clock, time.Time{}, nil},
		{&Information{Window: Window{clock, life.End.Add(time.Second)}, CheckedAt: clock, CheckAfter: clock.Add(time.Hour)}, clock, time.Time{}, nil},
		{&info, clock, time.Time{}, func(*big.Int) (*big.Int, error) { return nil, errors.New("entropy-sentinel") }},
		{&info, clock, time.Time{}, func(b *big.Int) (*big.Int, error) { return b, nil }},
		{&info, clock, time.Time{}, func(*big.Int) (*big.Int, error) { return big.NewInt(-1), nil }},
	} {
		pick := tc.pick
		if pick == nil {
			pick = func(*big.Int) (*big.Int, error) { return big.NewInt(0), nil }
		}
		s, err := selectAt(life, tc.info, tc.at, tc.wait, pick)
		if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(s, Selection{}) || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("bad scope/clock/backoff/entropy selected", s)
		}
	}
}

func identifierFixture(t testing.TB, serial *big.Int, aki []byte, ca bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic ARI parent"}, SubjectKeyId: aki, NotBefore: clock.Add(-time.Hour), NotAfter: clock.Add(90 * 24 * time.Hour)}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic ARI fixture"}, DNSNames: []string{"ari.rootwell.invalid"}, NotBefore: clock, NotAfter: clock.Add(24 * time.Hour), IsCA: ca, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestARICertificateIDPreservesPositiveSerialPaddingAndHasNoTrustClaim(t *testing.T) {
	aki, _ := hex.DecodeString("69885b6b87464041e1b37b847ba0ae2cde01c8d4")
	serial := new(big.Int).SetUint64(0x87654321)
	der := identifierFixture(t, serial, aki, false)
	before := bytes.Clone(der)
	id, err := CertificateID(der)
	if err != nil || id != "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" || !bytes.Equal(before, der) {
		t.Fatal("RFC identifier lost DER leading zero", id, err)
	}
	for _, bad := range [][]byte{nil, []byte("PRIVATE KEY error-sentinel"), bytes.Repeat([]byte{0}, 65537), append(bytes.Clone(der), 0), identifierFixture(t, big.NewInt(0), aki, false), identifierFixture(t, serial, nil, false), identifierFixture(t, serial, aki, true), identifierFixture(t, new(big.Int).Lsh(big.NewInt(1), 160), aki, false)} {
		id, err := CertificateID(bad)
		if !errors.Is(err, ErrInvalid) || id != "" || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("invalid certificate exposed identifier")
		}
	}
}

func FuzzARIInformation(f *testing.F) {
	f.Add([]byte(information), "21600")
	f.Add([]byte(`{"suggestedWindow":null}`), "0")
	f.Fuzz(func(t *testing.T, body []byte, hint string) {
		if len(body) > MaxInformationBytes+1 || len(hint) > 65 {
			t.Skip()
		}
		before := bytes.Clone(body)
		i, err := ParseInformation(body, []string{hint}, clock)
		if !bytes.Equal(body, before) {
			t.Fatal("input mutated")
		}
		if err != nil && !reflect.DeepEqual(i, Information{}) {
			t.Fatal("partial parse")
		}
		if err == nil && (!validWindow(i.Window) || i.CheckAfter.Sub(clock) < time.Minute || i.CheckAfter.Sub(clock) > 24*time.Hour) {
			t.Fatal("unbounded information")
		}
	})
}

func FuzzARICertificateID(f *testing.F) {
	f.Add(identifierFixture(f, big.NewInt(128), []byte{1, 2, 3}, false))
	f.Add([]byte("not a certificate"))
	f.Fuzz(func(t *testing.T, der []byte) {
		if len(der) > 65537 {
			t.Skip()
		}
		id, err := CertificateID(der)
		if err != nil && id != "" {
			t.Fatal("partial ID")
		}
		if err == nil && (len(id) > 128 || strings.ContainsAny(id, "=/\\?# \r\n")) {
			t.Fatal("unsafe public path component")
		}
	})
}

func FuzzRenewalSelection(f *testing.F) {
	f.Add(clock.Unix(), clock.Add(90*24*time.Hour).Unix(), clock.Unix(), int64(0))
	f.Add(clock.Unix(), clock.Add(24*time.Hour).Unix(), clock.Add(time.Hour).Unix(), clock.Add(2*time.Hour).Unix())
	f.Add(int64(0), int64(0), int64(0), int64(0))
	f.Fuzz(func(t *testing.T, start, end, now, wait int64) {
		lifetime := Window{time.Unix(start, 0), time.Unix(end, 0)}
		at := time.Unix(now, 0)
		var notBefore time.Time
		if wait != 0 {
			notBefore = time.Unix(wait, 0)
		}
		s, err := Select(lifetime, nil, at, notBefore)
		if err != nil {
			if !reflect.DeepEqual(s, Selection{}) {
				t.Fatal("partial selection")
			}
			return
		}
		if s.Source != "fallback" || s.At.Before(at) || s.At.Before(notBefore) || !s.At.Before(lifetime.End) {
			t.Fatal("selection escaped lifetime/backoff")
		}
	})
}
