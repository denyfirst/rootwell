package instanceaccess

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func readyV2Fixture(t *testing.T) (string, string, []byte, []byte) {
	t.Helper()
	path := accessPath(t)
	password := "a sufficiently long installation password"
	key := bytes.Repeat([]byte{0x93}, 32)
	id := bytes.Repeat([]byte{0x58}, 16)
	body, err := seal(key, password, ready, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, password, key, id
}

func TestRecoveryEnrollmentRotationAndPasswordResetPreserveIdentity(t *testing.T) {
	path, password, key, id := readyV2Fixture(t)
	oldCode, err := changeRecoveryLocked(path, password, "", recoveryEnroll, replace, func(string) error { return nil })
	if err != nil || len(oldCode) != 64 {
		t.Fatalf("enrollment failed: %v", err)
	}
	opened, openedID, err := OpenWithIdentity(path, password)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(openedID, id) {
		t.Fatalf("enrollment changed the key or identity: %v", err)
	}
	clear(opened)
	if _, err := changeRecoveryLocked(path, password, "", recoveryEnroll, replace, func(string) error { return nil }); !errors.Is(err, ErrRecoveryExists) {
		t.Fatalf("duplicate enrollment accepted: %v", err)
	}
	newCode, err := changeRecoveryLocked(path, password, "", recoveryRotate, replace, func(string) error { return nil })
	if err != nil || newCode == oldCode {
		t.Fatalf("code rotation failed: %v", err)
	}
	const nextPassword = "a new sufficiently long login password"
	if _, err := changeRecoveryLocked(path, oldCode, nextPassword, recoveryResetPassword, replace, func(string) error { return nil }); !errors.Is(err, ErrInvalidRecovery) {
		t.Fatalf("retired code reset password: %v", err)
	}
	thirdCode, err := changeRecoveryLocked(path, newCode, nextPassword, recoveryResetPassword, replace, func(string) error { return nil })
	if err != nil || thirdCode == newCode {
		t.Fatalf("password recovery failed: %v", err)
	}
	if _, err := Open(path, password); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("old password still works: %v", err)
	}
	opened, openedID, err = OpenWithIdentity(path, nextPassword)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(openedID, id) {
		t.Fatalf("recovery did not preserve key and ID: %v", err)
	}
	clear(opened)
	if _, err := changeRecoveryLocked(path, newCode, "another sufficiently long password", recoveryResetPassword, replace, func(string) error { return nil }); !errors.Is(err, ErrInvalidRecovery) {
		t.Fatalf("used code reset password again: %v", err)
	}
}

func TestRecoveryWrapSurvivesPasswordRotation(t *testing.T) {
	path, password, key, _ := readyV2Fixture(t)
	code, err := changeRecoveryLocked(path, password, "", recoveryEnroll, replace, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	const next = "a second sufficiently long password"
	if err := ChangePassword(path, password, next); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path, next)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("password rotation changed the data key: %v", err)
	}
	clear(opened)
	if _, err := changeRecoveryLocked(path, code, "a third sufficiently long password", recoveryResetPassword, replace, func(string) error { return nil }); err != nil {
		t.Fatalf("password rotation broke recovery: %v", err)
	}
}

func TestRecoveryRefusesWrongCredentialAndTamperedEnvelopeWithoutWriting(t *testing.T) {
	path, password, _, _ := readyV2Fixture(t)
	writeCalled := false
	spy := func(string, []byte) error { writeCalled = true; return nil }
	if _, err := changeRecoveryLocked(path, "incorrect password", "", recoveryEnroll, spy, func(string) error { return nil }); !errors.Is(err, ErrWrongPassword) || writeCalled {
		t.Fatalf("wrong password reached write: %v", err)
	}
	code, err := changeRecoveryLocked(path, password, "", recoveryEnroll, replace, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changeRecoveryLocked(path, "incorrect password", "", recoveryEnroll, spy, func(string) error { return nil }); !errors.Is(err, ErrWrongPassword) || writeCalled {
		t.Fatalf("unauthenticated caller learned enrollment state or reached write: %v", err)
	}
	if _, err := changeRecoveryLocked(path, "bad-code", "a sufficiently long new password", recoveryResetPassword, spy, func(string) error { return nil }); !errors.Is(err, ErrInvalidRecovery) || writeCalled {
		t.Fatalf("bad code reached write: %v", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e envelope
	if err := json.Unmarshal(original, &e); err != nil {
		t.Fatal(err)
	}
	e.RecoveryCheck[0] ^= 1
	altered, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := changeRecoveryLocked(path, code, "a sufficiently long new password", recoveryResetPassword, spy, func(string) error { return nil }); !errors.Is(err, ErrInvalidRecovery) || writeCalled {
		t.Fatalf("tampered commitment reached write: %v", err)
	}
	if _, err := Open(path, password); !errors.Is(err, ErrWrongPassword) && !errors.Is(err, ErrInvalidAccess) {
		t.Fatalf("tampered envelope was accepted: %v", err)
	}
}

func TestRecoveryWriteFaultsDoNotReturnCode(t *testing.T) {
	path, password, _, _ := readyV2Fixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	prewrite := errors.New("simulated prewrite fault")
	code, err := changeRecoveryLocked(path, password, "", recoveryEnroll,
		func(string, []byte) error { return prewrite }, func(string) error { t.Fatal("sync after failed write"); return nil })
	if code != "" || !errors.Is(err, prewrite) {
		t.Fatalf("prewrite fault returned a code: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("prewrite fault changed source: %v", err)
	}
	code, err = changeRecoveryLocked(path, password, "", recoveryEnroll,
		func(string, []byte) error { return nil }, func(string) error { return nil })
	if code != "" || !errors.Is(err, ErrWriteUncertain) {
		t.Fatalf("readback mismatch returned a code or definite result: %v", err)
	}
	code, err = changeRecoveryLocked(path, password, "", recoveryEnroll, replace,
		func(string) error { return errors.New("simulated postwrite sync fault") })
	if code != "" || !errors.Is(err, ErrWriteUncertain) {
		t.Fatalf("postwrite fault returned a code or definite result: %v", err)
	}
	if _, err := Open(path, password); err != nil {
		t.Fatalf("postwrite fault made login impossible: %v", err)
	}
}

func FuzzRecoveryEnvelopeParsing(f *testing.F) {
	f.Add([]byte("{"), "a sufficiently long password")
	f.Add(bytes.Repeat([]byte{0xff}, maxFile+1), "wrong")
	f.Fuzz(func(t *testing.T, body []byte, password string) {
		_, _, _, _ = unsealBody(body, password)
	})
}
