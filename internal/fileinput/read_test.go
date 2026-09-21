package fileinput

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	path := t.TempDir() + "/certificate.data"
	want := []byte("bounded input")
	if err := writeFixture(path, want); err != nil {
		t.Fatal(err)
	}

	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Read() = %q, want %q", got, want)
	}
}

func TestReadDoesNotExposePath(t *testing.T) {
	const secretPath = "/private/customer/secret-certificate.pem"
	_, err := Read(secretPath)
	if !errors.Is(err, ErrUnreadable) {
		t.Fatalf("Read() error = %v, want ErrUnreadable", err)
	}
	if strings.Contains(err.Error(), "customer") || strings.Contains(err.Error(), secretPath) {
		t.Fatalf("Read() exposed the input path: %q", err)
	}
}

func TestReadLimited(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		limit   int64
		wantErr error
	}{
		{name: "empty", limit: 4, wantErr: ErrEmpty},
		{name: "below limit", input: []byte("abc"), limit: 4},
		{name: "at limit", input: []byte("abcd"), limit: 4},
		{name: "above limit", input: []byte("abcde"), limit: 4, wantErr: ErrTooLarge},
		{name: "invalid limit", input: []byte("a"), wantErr: ErrUnreadable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := readLimited(bytes.NewReader(test.input), test.limit)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("readLimited() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && !bytes.Equal(got, test.input) {
				t.Fatalf("readLimited() = %q, want %q", got, test.input)
			}
		})
	}
}

func TestReadLimitedMapsReaderFailure(t *testing.T) {
	_, err := readLimited(errorReader{}, 32)
	if !errors.Is(err, ErrUnreadable) {
		t.Fatalf("readLimited() error = %v, want ErrUnreadable", err)
	}
}

func FuzzReadLimited(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("certificate"))
	f.Add(bytes.Repeat([]byte{'x'}, 4097))

	f.Fuzz(func(t *testing.T, input []byte) {
		const limit = int64(4096)
		got, err := readLimited(bytes.NewReader(input), limit)
		switch {
		case len(input) == 0:
			if !errors.Is(err, ErrEmpty) {
				t.Fatalf("empty input error = %v, want ErrEmpty", err)
			}
		case int64(len(input)) > limit:
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("oversized input error = %v, want ErrTooLarge", err)
			}
		default:
			if err != nil {
				t.Fatalf("bounded input error = %v", err)
			}
			if !bytes.Equal(got, input) {
				t.Fatal("bounded input changed while being read")
			}
		}
	})
}

func writeFixture(path string, contents []byte) error {
	return os.WriteFile(path, contents, 0o600)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("sensitive underlying error")
}
