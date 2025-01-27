package metadata

import (
	"encoding/json"
	"time"

	"gh-attest-util/internal/attestation/schema"
)

const PredicateTypeURI = "https://cosign.sigstore.dev/attestation/v1"

type Metadata struct {
	schema.Metadata
}

type Options struct {
	SubjectName     string
	SubjectPath     string
	Digest          string
	Version         string
	Created         time.Time
	Type            string
	Registry        string
	FullName        string
	Repository      string
	RepositoryID    string
	GitHubServerURL string
	Owner           string
	OwnerID         string
	OS              string
	Arch            string
	Environment     string
	WorkflowRefPath string
	Inputs          map[string]any
	Branch          string
	Event           string
	RunNumber       string
	RunID           string
	Status          string
	TriggeredBy     string
	StartedAt       time.Time
	CompletedAt     time.Time
	SHA             string
	Timestamp       time.Time
	Organization    string
	PolicyRef       string
	ControlIds      []string
	Permissions     map[string]string
}

func (m *Metadata) Type() string {
	return PredicateTypeURI
}

func (m *Metadata) Generate() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func NewFromOptions(opts Options) (*Metadata, error) {
	m := &Metadata{
		Metadata: schema.Metadata{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: PredicateTypeURI,
			Subject: []schema.Subject{
				{
					Name: opts.SubjectName,
					Digest: struct {
						SHA256 string `json:"sha256"`
					}{
						SHA256: opts.Digest,
					},
				},
			},
		},
	}

	m.Predicate.Artifact.Version = opts.Version
	m.Predicate.Artifact.Created = opts.Created.Format(time.RFC3339)
	m.Predicate.Artifact.Type = opts.Type
	m.Predicate.Artifact.Registry = opts.Registry
	m.Predicate.Artifact.FullName = opts.FullName
	m.Predicate.Artifact.Digest = opts.Digest

	m.Predicate.RepositoryData.Repository = opts.Repository
	m.Predicate.RepositoryData.RepositoryID = opts.RepositoryID
	m.Predicate.RepositoryData.GitHubServerURL = opts.GitHubServerURL

	m.Predicate.OwnerData.Owner = opts.Owner
	m.Predicate.OwnerData.OwnerID = opts.OwnerID

	m.Predicate.RunnerData.OS = opts.OS
	m.Predicate.RunnerData.Arch = opts.Arch
	m.Predicate.RunnerData.Environment = opts.Environment

	m.Predicate.WorkflowData.WorkflowRefPath = opts.WorkflowRefPath
	m.Predicate.WorkflowData.Inputs = opts.Inputs
	m.Predicate.WorkflowData.Branch = opts.Branch
	m.Predicate.WorkflowData.Event = opts.Event

	m.Predicate.JobData.RunNumber = opts.RunNumber
	m.Predicate.JobData.RunID = opts.RunID
	m.Predicate.JobData.Status = opts.Status
	m.Predicate.JobData.TriggeredBy = opts.TriggeredBy
	m.Predicate.JobData.StartedAt = opts.StartedAt.Format(time.RFC3339)
	m.Predicate.JobData.CompletedAt = opts.CompletedAt.Format(time.RFC3339)

	m.Predicate.CommitData.SHA = opts.SHA
	m.Predicate.CommitData.Timestamp = opts.Timestamp.Format(time.RFC3339)

	m.Predicate.Organization.Name = opts.Organization

	m.Predicate.Compliance.PolicyRef = opts.PolicyRef
	m.Predicate.Compliance.ControlIds = opts.ControlIds

	m.Predicate.Security.Permissions = opts.Permissions

	return m, nil
}
