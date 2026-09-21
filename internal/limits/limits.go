// Package limits defines resource limits shared by Rootwell's input boundaries.
package limits

const (
	// MaxInputBytes is the largest single object Rootwell will read into memory.
	MaxInputBytes int64 = 16 << 20
	// MaxMetadataTextBytes limits certificate-derived text before terminal
	// escaping can amplify it.
	MaxMetadataTextBytes = 1 << 20
	// MaxMetadataValues limits repeated certificate metadata fields.
	MaxMetadataValues = 4096
)
