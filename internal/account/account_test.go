package account

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPasswordsHashAndVerifyWithOneLimit(t *testing.T) {
	good := "kitchen-river-lantern-74"
	h, err := HashPassword(good)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Verify(good) || h.Verify(good+" ") || h.Verify("kitchen-river-lantern-75") {
		t.Fatal("verify does not match exactly")
	}
	other, _ := HashPassword(good)
	if bytes.Equal(h.Salt, other.Salt) || bytes.Equal(h.Sum, other.Sum) {
		t.Fatal("two hashes of one password share a salt or a sum")
	}
	if fmt.Sprint(h) != "[password hash]" || strings.Contains(fmt.Sprintf("%v %+v", h, h), hex.EncodeToString(h.Sum)) {
		t.Fatal("a hash prints its value")
	}
	longest := strings.Repeat("ab3", MaxPasswordBytes/3) + "x"
	if len(longest) != MaxPasswordBytes {
		t.Fatalf("fixture length %d", len(longest))
	}
	hl, err := HashPassword(longest)
	if err != nil || !hl.Verify(longest) {
		t.Fatalf("the longest allowed password must set and verify alike (RW-09): %v", err)
	}
	for _, bad := range []string{"", "short-pass-1", strings.Repeat("x", MaxPasswordBytes+1), "password123456789"[:0] + "passwordpassword",
		"correcthorsebatterystaple", "abababababababababab", "aaaaaaaaaaaaaaaaaaaa", "1234567890123456", "abcdefghijklmnopq", "9876543210987654", "\xff\xfe-not-utf8-really-long"} {
		if _, err := HashPassword(bad); err == nil {
			t.Errorf("%q was accepted as a new password", bad)
		}
	}
	if h.Verify(strings.Repeat("x", MaxPasswordBytes+1)) {
		t.Fatal("an over-long password verified")
	}
	broken := h
	broken.Salt = broken.Salt[:8]
	if broken.Verify(good) || (PasswordHash{}).Verify(good) {
		t.Fatal("a malformed hash verified")
	}
}

// The list is SecLists' 10k file as Keybash pins it, byte for byte.
func TestTheCommonPasswordListIsThePinnedOne(t *testing.T) {
	sum := sha256.Sum256([]byte(commonPasswords))
	if hex.EncodeToString(sum[:]) != "68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce" {
		t.Fatalf("the password list changed: %x", sum)
	}
	if len(blockedPasswords) < 9000 {
		t.Fatalf("only %d blocked passwords", len(blockedPasswords))
	}
}

// RFC 6238 appendix B's SHA-1 key, cut to the six digits authenticator apps show.
func TestCodesMatchRFC6238AndAreNeverAcceptedTwice(t *testing.T) {
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, c := range []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		step, ok := CheckCode(seed, c.code, time.Unix(c.unix, 0), -1)
		if !ok || step != c.unix/30 {
			t.Fatalf("RFC 6238 vector at %d: %v %d", c.unix, ok, step)
		}
		if _, again := CheckCode(seed, c.code, time.Unix(c.unix, 0), step); again {
			t.Fatalf("the code at %d was accepted twice", c.unix)
		}
	}
	// One step either side is accepted; two are not.
	at := time.Unix(1111111109, 0)
	if _, ok := CheckCode(seed, "081804", at.Add(30*time.Second), -1); !ok {
		t.Fatal("a code from one step before was refused")
	}
	if _, ok := CheckCode(seed, "081804", at.Add(-30*time.Second), -1); !ok {
		t.Fatal("a code from one step after was refused")
	}
	// The code belongs to step 37037036; these instants are in steps +2 and -2.
	if _, ok := CheckCode(seed, "081804", at.Add(31*time.Second), -1); ok {
		t.Fatal("a code from two steps before was accepted")
	}
	if _, ok := CheckCode(seed, "081804", at.Add(-61*time.Second), -1); ok {
		t.Fatal("a code from two steps after was accepted")
	}
	for _, bad := range []string{"", "28708", "2870822", "28708a", " 287082", "２８７０８２"} {
		if _, ok := CheckCode(seed, bad, time.Unix(59, 0), -1); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, badSeed := range []string{"", "not base32!", strings.ToLower(seed), seed + "A"} {
		if _, ok := CheckCode(badSeed, "287082", time.Unix(59, 0), -1); ok {
			t.Errorf("seed %q was accepted", badSeed)
		}
	}
}

func TestNewSeedsDrawAsAuthenticatorQRCodes(t *testing.T) {
	seed, err := NewSeed()
	if err != nil || len(seed) != 32 {
		t.Fatalf("seed %q: %v", seed, err)
	}
	other, _ := NewSeed()
	if other == seed {
		t.Fatal("two seeds are equal")
	}
	uri, err := SeedURI("admin", seed)
	if err != nil || uri != "otpauth://totp/Rootwell:admin?secret="+seed+"&issuer=Rootwell" {
		t.Fatalf("uri %q: %v", uri, err)
	}
	rows, err := SeedQR("admin", seed)
	if err != nil || len(rows) < 21 || len(rows[0]) != len(rows) || strings.Trim(strings.Join(rows, ""), "01") != "" {
		t.Fatalf("qr rows: %v", err)
	}
	for _, name := range []string{"", ".admin", "a b", "a/b", "a?b=c", strings.Repeat("a", 65), "ümit"} {
		if _, err := SeedURI(name, seed); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
}

func TestRecoveryCodesWorkOnceInAnyCase(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	codes, digests, err := NewRecoveryCodes(key)
	if err != nil || len(codes) != RecoveryCodeCount || len(digests) != RecoveryCodeCount {
		t.Fatalf("codes: %v", err)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != 19 || strings.Count(code, "-") != 3 || seen[code] {
			t.Fatalf("code %q", code)
		}
		seen[code] = true
	}
	rest, ok := UseRecoveryCode(key, strings.ToUpper(strings.ReplaceAll(codes[3], "-", "")), digests)
	if !ok || len(rest) != RecoveryCodeCount-1 {
		t.Fatal("a code typed in capitals without dashes was refused")
	}
	if _, again := UseRecoveryCode(key, codes[3], rest); again {
		t.Fatal("a recovery code worked twice")
	}
	if _, wrongKey := UseRecoveryCode(bytes.Repeat([]byte{8}, 32), codes[4], rest); wrongKey {
		t.Fatal("a code matched under another account's key")
	}
	if _, ok := UseRecoveryCode(key, codes[4], rest); !ok {
		t.Fatal("an unused code was refused")
	}
	for _, digest := range digests {
		for _, code := range codes {
			if bytes.Contains(digest, []byte(code)) {
				t.Fatal("a digest carries its code")
			}
		}
	}
}

func TestBootstrapCodesAreLongAndKeyed(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	code, digest, err := NewBootstrapCode(key)
	if err != nil || len(code) != 27 || strings.Count(code, "-") != 3 {
		t.Fatalf("code %q: %v", code, err)
	}
	if !bytes.Equal(CodeDigest(key, strings.ToUpper(code)), digest) {
		t.Fatal("the typed code does not match its digest")
	}
	second, _, _ := NewBootstrapCode(key)
	if second == code {
		t.Fatal("two bootstrap codes are equal")
	}
	if _, _, err := NewBootstrapCode(key[:31]); err == nil {
		t.Fatal("a short digest key was accepted")
	}
}
