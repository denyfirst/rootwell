// Package fileformat reads one file a person chose and says what it holds:
// a PFX, certificates, one private key, or certificates with their key. It
// returns each part in the strict form the rest of Rootwell accepts, so the
// strict readers, and the server, stay as they are.
//
// Beyond those strict forms it reads what real tools write: a UTF-8 byte
// order mark, CRLF lines, printable text between PEM blocks (OpenSSL's "Bag
// Attributes", "subject=" and "issuer=" lines), PKCS#7 certificate bundles,
// an "EC PARAMETERS" block before its EC key, and old OpenSSL encrypted PEM
// keys. Base64 inside a block stays strict, and nothing is skipped silently:
// an unknown block, a second key or a broken block refuses the whole file.
package fileformat

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/legacypemkey"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/denyfirst/rootwell/internal/pkcs7certs"
)

var (
	ErrEmpty               = errors.New("the file is empty")
	ErrTooLarge            = errors.New("the file is too large")
	ErrUnreadable          = errors.New("the file is not a certificate, key or PFX Rootwell reads")
	ErrUnexpectedText      = errors.New("the file holds text that is not part of a certificate or key")
	ErrUnknownBlock        = errors.New("the file holds a kind of PEM block Rootwell does not read")
	ErrCertificateRequest  = errors.New("the file is a certificate request")
	ErrBadCertificate      = errors.New("the file holds a damaged certificate")
	ErrSeveralKeys         = errors.New("the file holds more than one private key")
	ErrTooManyCertificates = errors.New("the file holds more than 64 certificates")
	ErrPKCS7               = errors.New("the PKCS#7 bundle holds something other than certificates")
	ErrKeyParameters       = errors.New("the EC parameters do not belong to the key")
	ErrNoKey               = errors.New("the file holds no private key")
	ErrPasswordRequired    = errors.New("the key is locked with a password")
	ErrWrongPassword       = errors.New("the password does not open the key")
)

var byteOrderMark = []byte{0xef, 0xbb, 0xbf}

// Parts is what one file holds, each part in a strict form.
type Parts struct {
	// PFX is set alone: the file is a PFX, to be opened with its password.
	PFX bool
	// Certificates holds header-free PEM CERTIFICATE blocks, in file order.
	Certificates []byte
	Count        int
	// Key is one private key: a header-free PEM block, or the DER the file
	// held. An old-style encrypted key keeps its two headers for Unlock.
	Key         []byte
	KeyLocked   bool
	KeyOldStyle bool
}

// Clear wipes the parts that may hold key material.
func (p *Parts) Clear() {
	clear(p.Key)
	clear(p.Certificates)
	*p = Parts{}
}

// Split reads one file. Its error names what is wrong with this file.
func Split(input []byte) (Parts, error) {
	if len(input) == 0 {
		return Parts{}, ErrEmpty
	}
	if int64(len(input)) > limits.MaxInputBytes {
		return Parts{}, ErrTooLarge
	}
	text := bytes.TrimPrefix(input, byteOrderMark)
	if len(bytes.TrimSpace(text)) == 0 {
		return Parts{}, ErrEmpty
	}
	if printable(text) {
		return splitText(text)
	}
	if len(text) != len(input) {
		// A byte order mark belongs only before text.
		return Parts{}, ErrUnreadable
	}
	return splitBinary(input)
}

func splitBinary(input []byte) (Parts, error) {
	switch {
	case pfxinspect.IsPFX(input):
		return Parts{PFX: true}, nil
	case pkcs7certs.IsPKCS7(input):
		certificates, err := pkcs7certs.Parse(input)
		if err != nil {
			return Parts{}, ErrPKCS7
		}
		return certificatePart(certificates), nil
	}
	if _, _, err := certinspect.Parse(input); err == nil {
		return certificatePart([][]byte{bytes.Clone(input)}), nil
	}
	if int64(len(input)) > limits.MaxPrivateKeyBytes {
		return Parts{}, ErrUnreadable
	}
	if keymatch.WithPrivateKey(input, func(any, keymatch.Encoding) error { return nil }) == nil {
		return Parts{Key: bytes.Clone(input)}, nil
	}
	if encryptedPKCS8Shape(input) {
		return Parts{Key: bytes.Clone(input), KeyLocked: true}, nil
	}
	return Parts{}, ErrUnreadable
}

// encryptedPKCS8Shape recognises an EncryptedPrivateKeyInfo without
// judging its protection; the strict key reader does that with the password.
func encryptedPKCS8Shape(input []byte) bool {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	rest, err := asn1.Unmarshal(input, &info)
	return err == nil && len(rest) == 0 && len(info.Algorithm.Algorithm) != 0 && len(info.Data) != 0
}

func certificatePart(certificates [][]byte) Parts {
	var out []byte
	for _, der := range certificates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return Parts{Certificates: out, Count: len(certificates)}
}

// printable is text a person or a tool wrote: valid UTF-8 without control
// characters other than tab, CR and LF. DER is never printable.
func printable(input []byte) bool {
	for len(input) != 0 {
		r, size := utf8.DecodeRune(input)
		if r == utf8.RuneError && size <= 1 {
			return false
		}
		if r != '\t' && r != '\r' && r != '\n' && r != 0xfeff && !unicode.IsPrint(r) {
			return false
		}
		input = input[size:]
	}
	return true
}

func lineStart(text []byte, at int) bool { return at == 0 || text[at-1] == '\n' }

// nextBegin finds the next BEGIN line at the start of a line.
func nextBegin(text []byte) int {
	for offset := 0; ; {
		index := bytes.Index(text[offset:], []byte("-----BEGIN "))
		if index < 0 {
			return -1
		}
		if lineStart(text, offset+index) {
			return offset + index
		}
		offset += index + 1
	}
}

// outside checks text between blocks: printable lines, none of which looks
// like a PEM boundary that lost its partner.
func outside(text []byte) error {
	for _, line := range bytes.Split(text, []byte("\n")) {
		if bytes.HasPrefix(bytes.TrimLeft(bytes.ReplaceAll(line, byteOrderMark, nil), " \t"), []byte("-----")) {
			return ErrUnreadable
		}
	}
	return nil
}

func splitText(text []byte) (Parts, error) {
	var certificates [][]byte
	var parts Parts
	fail := func(err error) (Parts, error) {
		parts.Clear()
		return Parts{}, err
	}
	var curve asn1.ObjectIdentifier
	sawParameters := false
	for rest := text; ; {
		begin := nextBegin(rest)
		if begin < 0 {
			if err := outside(rest); err != nil {
				return fail(err)
			}
			break
		}
		if err := outside(rest[:begin]); err != nil {
			return fail(err)
		}
		block, after, err := oneBlock(rest[begin:])
		if err != nil {
			return fail(err)
		}
		rest = after
		switch block.Type {
		case "CERTIFICATE":
			if len(block.Headers) != 0 {
				return fail(ErrUnknownBlock)
			}
			if _, _, err := certinspect.Parse(block.Bytes); err != nil {
				return fail(ErrBadCertificate)
			}
			certificates = append(certificates, block.Bytes)
		case "PKCS7", "PKCS #7 SIGNED DATA":
			if len(block.Headers) != 0 {
				return fail(ErrUnknownBlock)
			}
			bundle, err := pkcs7certs.Parse(block.Bytes)
			if err != nil {
				return fail(ErrPKCS7)
			}
			certificates = append(certificates, bundle...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			if parts.Key != nil {
				clear(block.Bytes)
				return fail(ErrSeveralKeys)
			}
			switch {
			case legacypemkey.IsEncrypted(block):
				parts.Key = pem.EncodeToMemory(block)
				parts.KeyLocked, parts.KeyOldStyle = true, true
			case len(block.Headers) != 0:
				clear(block.Bytes)
				return fail(ErrUnknownBlock)
			default:
				parts.Key = pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})
				parts.KeyLocked = block.Type == "ENCRYPTED PRIVATE KEY"
			}
			clear(block.Bytes)
		case "EC PARAMETERS":
			if sawParameters || len(block.Headers) != 0 {
				return fail(ErrKeyParameters)
			}
			// Only a named curve, never explicit curve parameters.
			if rest, err := asn1.Unmarshal(block.Bytes, &curve); err != nil || len(rest) != 0 {
				return fail(ErrKeyParameters)
			}
			sawParameters = true
		case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
			return fail(ErrCertificateRequest)
		default:
			return fail(ErrUnknownBlock)
		}
		if len(certificates) > limits.MaxCertificatesPerBundle {
			return fail(ErrTooManyCertificates)
		}
	}
	if sawParameters && !keyOnCurve(parts, curve) {
		return fail(ErrKeyParameters)
	}
	if len(certificates) == 0 && parts.Key == nil {
		return fail(ErrUnreadable)
	}
	if len(certificates) != 0 {
		parts.Certificates = certificatePart(certificates).Certificates
		parts.Count = len(certificates)
	}
	return parts, nil
}

// oneBlock decodes exactly the block that starts text. pem.Decode alone
// would skip a broken block and return the next one.
func oneBlock(text []byte) (*pem.Block, []byte, error) {
	lineEnd := bytes.IndexByte(text, '\n')
	if lineEnd < 0 {
		return nil, nil, ErrUnreadable
	}
	label := bytes.TrimRight(text[:lineEnd], " \t\r")
	if !bytes.HasSuffix(label, []byte("-----")) || len(label) <= len("-----BEGIN ")+len("-----") {
		return nil, nil, ErrUnreadable
	}
	kind := label[len("-----BEGIN ") : len(label)-len("-----")]
	end := []byte("-----END " + string(kind) + "-----")
	endIndex := bytes.Index(text, end)
	if endIndex < 0 {
		return nil, nil, ErrUnreadable
	}
	segment := text[:endIndex+len(end)]
	if bytes.Count(segment, []byte("-----BEGIN ")) != 1 {
		return nil, nil, ErrUnreadable
	}
	block, rest := pem.Decode(segment)
	if block == nil || block.Type != string(kind) || len(bytes.TrimSpace(rest)) != 0 || len(block.Bytes) == 0 {
		return nil, nil, ErrUnreadable
	}
	return block, text[len(segment):], nil
}

// keyOnCurve checks that a key read with an EC PARAMETERS block is an
// unencrypted EC key on that same named curve.
func keyOnCurve(parts Parts, curve asn1.ObjectIdentifier) bool {
	if parts.Key == nil || parts.KeyLocked {
		return false
	}
	block, _ := pem.Decode(parts.Key)
	if block == nil {
		return false
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "EC PRIVATE KEY":
		var key struct {
			Version    int
			PrivateKey []byte
			Curve      asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
			PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
		}
		rest, err := asn1.Unmarshal(block.Bytes, &key)
		defer clear(key.PrivateKey)
		return err == nil && len(rest) == 0 && key.Curve.Equal(curve)
	case "PRIVATE KEY":
		var key struct {
			Version    int
			Algorithm  pkix.AlgorithmIdentifier
			PrivateKey []byte
		}
		rest, err := asn1.Unmarshal(block.Bytes, &key)
		defer clear(key.PrivateKey)
		var named asn1.ObjectIdentifier
		if err != nil || len(rest) != 0 || !key.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) {
			return false
		}
		tail, err := asn1.Unmarshal(key.Algorithm.Parameters.FullBytes, &named)
		return err == nil && len(tail) == 0 && named.Equal(curve)
	}
	return false
}

// Unlock opens an old-style encrypted key from Split and returns it as a
// header-free PKCS#1 or SEC 1 PEM block. The caller must clear it.
func Unlock(key, password []byte) ([]byte, error) {
	block, rest := pem.Decode(key)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || !legacypemkey.IsEncrypted(block) {
		return nil, ErrUnreadable
	}
	defer clear(block.Bytes)
	if len(password) == 0 {
		return nil, ErrPasswordRequired
	}
	der, err := legacypemkey.Decrypt(block, password)
	switch {
	case errors.Is(err, legacypemkey.ErrWrongPassword):
		return nil, ErrWrongPassword
	case err != nil:
		return nil, ErrUnknownBlock
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der}), nil
}

// Key prepares one chosen key file for the strict key readers. It returns
// the key, and the password to give them with it: an old-style key comes
// back opened, with no password. A file that holds no key goes back as it
// was, so the strict reader refuses it in its usual words. The caller must
// clear a returned key that differs from input.
func Key(input, password []byte) ([]byte, []byte, error) {
	parts, err := Split(input)
	if err != nil || parts.Key == nil {
		parts.Clear()
		return input, password, nil
	}
	clear(parts.Certificates)
	if !parts.KeyOldStyle {
		return parts.Key, password, nil
	}
	defer clear(parts.Key)
	opened, err := Unlock(parts.Key, password)
	if err != nil {
		return nil, nil, err
	}
	return opened, nil, nil
}
