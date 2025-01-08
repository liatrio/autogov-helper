package attestation

type PredicateType interface {
	Type() string

	Generate() ([]byte, error)
}

type BaseAttestation struct {
	SubjectName string
	SubjectPath string
	Registry    string
}
