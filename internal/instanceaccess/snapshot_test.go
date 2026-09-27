package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func accessSnapshotFixture(t *testing.T) ([]byte, string, string, []byte, []byte) {
	t.Helper()
	path, password, key, id := readyV2Fixture(t)
	code, err := changeRecoveryLocked(path, password, "", recoveryEnroll, replace, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body, password, code, key, id
}

func TestAccessSnapshotVerifiesWithPasswordOrRecoveryCode(t *testing.T) {
	body, password, code, key, id := accessSnapshotFixture(t)
	first, err := createAccessSnapshot(body, password, code)
	if err != nil {
		t.Fatal(err)
	}
	second, err := createAccessSnapshot(body, password, code)
	if err != nil || bytes.Equal(first, second) || bytes.Contains(first, key) || bytes.Contains(first, []byte(password)) || bytes.Contains(first, []byte(code)) {
		t.Fatalf("snapshot reused randomness or leaked a secret: %v", err)
	}
	for _, method := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		credential := password
		if method == SnapshotRecoveryCode {
			credential = code
		}
		opened, openedID, err := openAccessSnapshot(first, credential, method)
		if err != nil || !bytes.Equal(opened, body) || !bytes.Equal(openedID, id) {
			t.Fatalf("valid snapshot was refused: %v", err)
		}
	}
}

func TestAccessSnapshotRejectsWrongCredentialsTamperingAndTruncation(t *testing.T) {
	body, password, code, _, _ := accessSnapshotFixture(t)
	if produced, err := createAccessSnapshot(body, password, "wrong-code"); produced != nil || !errors.Is(err, ErrInvalidRecovery) {
		t.Fatalf("snapshot exported without the enrolled code: %v", err)
	}
	snapshot, err := createAccessSnapshot(body, password, code)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{
		{"wrong password", SnapshotPassword},
		{"wrong-code", SnapshotRecoveryCode},
		{password, 0},
		{code, SnapshotPassword},
	} {
		opened, id, err := openAccessSnapshot(snapshot, tc.credential, tc.method)
		if !errors.Is(err, ErrInvalidSnapshot) || opened != nil || id != nil {
			t.Fatalf("invalid credential returned data: %v", err)
		}
	}
	for _, offset := range []int{0, len(snapshotMagic), len(snapshotMagic) + 16, len(snapshotMagic) + 20, len(snapshot) - 1} {
		changed := bytes.Clone(snapshot)
		changed[offset] ^= 1
		opened, id, err := openAccessSnapshot(changed, password, SnapshotPassword)
		if !errors.Is(err, ErrInvalidSnapshot) || opened != nil || id != nil {
			t.Fatalf("tampered offset %d returned data: %v", offset, err)
		}
	}
	for _, changed := range [][]byte{snapshot[:len(snapshot)-1], append(bytes.Clone(snapshot), 0), bytes.Repeat([]byte{1}, maxSnapshotFile+1)} {
		opened, id, err := openAccessSnapshot(changed, code, SnapshotRecoveryCode)
		if !errors.Is(err, ErrInvalidSnapshot) || opened != nil || id != nil {
			t.Fatalf("malformed length returned data: %v", err)
		}
	}
}

func TestAccessSnapshotRequiresEnrolledRecovery(t *testing.T) {
	path, password, _, _ := readyV2Fixture(t)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot, err := createAccessSnapshot(body, "wrong password", "irrelevant"); snapshot != nil || !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("unauthenticated caller learned recovery enrollment state: %v", err)
	}
	if snapshot, err := createAccessSnapshot(body, password, "irrelevant"); snapshot != nil || !errors.Is(err, ErrRecoveryMissing) {
		t.Fatalf("v2 installation produced an unrecoverable snapshot: %v", err)
	}
}

func FuzzOpenAccessSnapshot(f *testing.F) {
	f.Add([]byte(snapshotMagic), "wrong", uint8(SnapshotPassword))
	f.Add(bytes.Repeat([]byte{0}, maxSnapshotFile+1), "wrong", uint8(SnapshotRecoveryCode))
	f.Fuzz(func(t *testing.T, snapshot []byte, credential string, method uint8) {
		_, _, _ = openAccessSnapshot(snapshot, credential, SnapshotUnlock(method))
	})
}
