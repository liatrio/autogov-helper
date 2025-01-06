package attestation

// PredicateType represents a custom predicate type for attestations
type PredicateType interface {
	// Type returns the URI identifying this predicate type
	Type() string

	// Generate creates the predicate content
	Generate() ([]byte, error)
}

// BaseAttestation contains common fields for all attestations
type BaseAttestation struct {
	SubjectName string
	SubjectPath string
	Registry    string
}
