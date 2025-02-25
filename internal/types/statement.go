package types

// in-toto subject
type Subject struct {
	Name   string       `json:"name"`
	Digest DigestHolder `json:"digest"`
}

// sha256 digest holder
type DigestHolder struct {
	SHA256 string `json:"sha256"`
}

// in-toto statement constants
const (
	StatementType = "https://in-toto.io/Statement/v1"
)
