// Package limits defines resource limits shared by Rootwell's input boundaries.
package limits

const (
	// MaxInputBytes is the largest single object Rootwell will read into memory.
	MaxInputBytes int64 = 16 << 20
	// MaxPrivateKeyBytes is deliberately smaller than the public-object limit.
	// Supported private-key encodings are normally only a few KiB; this bound
	// reduces parser work on attacker-controlled big integers while leaving
	// generous room for the largest key Rootwell accepts.
	MaxPrivateKeyBytes int64 = 64 << 10
	// MaxPrivateKeyBits bounds accepted keys. RSA inputs receive a shallow
	// modulus-size check before standard-library private-key arithmetic.
	MaxPrivateKeyBits = 16384
	// MaxMetadataTextBytes limits certificate-derived text before terminal
	// escaping can amplify it.
	MaxMetadataTextBytes = 1 << 20
	// MaxMetadataValues limits repeated certificate metadata fields.
	MaxMetadataValues = 4096
	// MaxCertificatesPerBundle bounds trust and intermediate bundle work.
	MaxCertificatesPerBundle = 64
)
