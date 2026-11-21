package account

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 4226 and 6238 fix HMAC-SHA1 for authenticator apps; HMAC does not rely on SHA-1's collision resistance.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/qrcode"
)

var seedEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSeed returns a new authenticator key: 20 random bytes in base32.
func NewSeed() (string, error) {
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrRefused
	}
	defer clear(raw[:])
	return seedEncoding.EncodeToString(raw[:]), nil
}

func seedBytes(seed string) ([]byte, bool) {
	raw, err := seedEncoding.DecodeString(seed)
	if err != nil || len(raw) != 20 || seedEncoding.EncodeToString(raw) != seed {
		return nil, false
	}
	return raw, true
}

// SeedURI is the standard authenticator key URI. SHA1, six digits and 30
// seconds are the format's defaults and exactly what CheckCode accepts.
func SeedURI(name, seed string) (string, error) {
	if _, ok := seedBytes(seed); !ok || !nameInput(name) {
		return "", ErrRefused
	}
	// A valid name is letters, digits, dot, dash and underscore: nothing to escape,
	// and no URL package in a package the architecture keeps off the network.
	return "otpauth://totp/Rootwell:" + name + "?secret=" + seed + "&issuer=Rootwell", nil
}

// SeedQR draws the seed's URI as QR modules, one string per row with "1" for
// a dark module; the page adds the quiet zone.
func SeedQR(name, seed string) ([]string, error) {
	uri, err := SeedURI(name, seed)
	if err != nil {
		return nil, err
	}
	code, err := qrcode.Encode([]byte(uri))
	if err != nil {
		return nil, ErrRefused
	}
	rows := make([]string, len(code))
	for y, modules := range code {
		var row strings.Builder
		for _, dark := range modules {
			row.WriteByte(map[bool]byte{true: '1', false: '0'}[dark])
		}
		rows[y] = row.String()
	}
	return rows, nil
}

// hotp is RFC 4226 with six digits, as every authenticator app computes it.
func hotp(key []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, key) // #nosec G401 -- RFC 4226 HMAC-SHA1, as authenticator apps compute it.
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	at := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[at:at+4])&0x7fffffff)%1000000)
}

// CheckCode accepts a six-digit code from the 30-second steps before, at and
// after now, and only above the last step already used. It returns the step
// to keep, so no code is ever accepted twice.
func CheckCode(seed, code string, now time.Time, last int64) (int64, bool) {
	key, ok := seedBytes(seed)
	if !ok || len(code) != 6 || now.Unix() < 30 {
		return 0, false
	}
	defer clear(key)
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	current := now.Unix() / 30
	matched := int64(-1)
	for _, step := range []int64{current - 1, current, current + 1} {
		if step >= 0 && subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step))), []byte(code)) == 1 && step > last {
			matched = max(matched, step)
		}
	}
	return matched, matched >= 0
}

// RecoveryCodeCount is how many one-time recovery codes an account gets.
const RecoveryCodeCount = 10

var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewRecoveryCodes returns ten codes of 80 random bits, printed as
// "xxxx-xxxx-xxxx-xxxx", and their digests under the account's digest key.
// Only the digests are kept.
func NewRecoveryCodes(digestKey []byte) ([]string, [][]byte, error) {
	if len(digestKey) != 32 {
		return nil, nil, ErrRefused
	}
	codes := make([]string, RecoveryCodeCount)
	digests := make([][]byte, RecoveryCodeCount)
	for i := range codes {
		var raw [10]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, nil, ErrRefused
		}
		text := strings.ToLower(codeEncoding.EncodeToString(raw[:]))
		codes[i] = text[0:4] + "-" + text[4:8] + "-" + text[8:12] + "-" + text[12:16]
		digests[i] = CodeDigest(digestKey, codes[i])
	}
	return codes, digests, nil
}

// CodeDigest is the keyed digest kept for a one-time code. It accepts the
// code as printed, in either case, with or without separators.
func CodeDigest(digestKey []byte, code string) []byte {
	compact := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	mac := hmac.New(sha256.New, digestKey)
	_, _ = mac.Write([]byte("rootwell/one-time-code/v1/"))
	_, _ = mac.Write([]byte(compact))
	return mac.Sum(nil)
}

// UseRecoveryCode finds the code among the kept digests and returns the list
// without it; a code works once.
func UseRecoveryCode(digestKey []byte, code string, digests [][]byte) ([][]byte, bool) {
	if len(digestKey) != 32 || len(code) == 0 || len(code) > 64 {
		return digests, false
	}
	digest := CodeDigest(digestKey, code)
	for i, kept := range digests {
		if subtle.ConstantTimeCompare(kept, digest) == 1 {
			rest := append(append([][]byte{}, digests[:i]...), digests[i+1:]...)
			return rest, true
		}
	}
	return digests, false
}

// NewBootstrapCode is the one-time code `rootwelld init` prints for creating
// the first account: 120 random bits, "xxxxxx-xxxxxx-xxxxxx-xxxxxx", and its
// digest.
func NewBootstrapCode(digestKey []byte) (string, []byte, error) {
	if len(digestKey) != 32 {
		return "", nil, ErrRefused
	}
	var raw [15]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, ErrRefused
	}
	text := strings.ToLower(codeEncoding.EncodeToString(raw[:]))
	var code strings.Builder
	for i := 0; i < len(text); i += 6 {
		if i > 0 {
			code.WriteByte('-')
		}
		code.WriteString(text[i:min(i+6, len(text))])
	}
	return code.String(), CodeDigest(digestKey, code.String()), nil
}

// nameInput is an account name: 1 to 64 letters, digits, dot, dash or
// underscore, starting with a letter or digit.
func nameInput(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for i, c := range name {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '-' || c == '_')
		if !ok {
			return false
		}
	}
	return true
}

// ValidName reports whether a name can be an account name.
func ValidName(name string) bool { return nameInput(name) }
