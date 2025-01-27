package metadata

import (
	"encoding/json"
	"time"

	"gh-attest-util/internal/validation"
)

const PredicateTypeURI = "https://cosign.sigstore.dev/attestation/v1"

// ArtifactType represents the type of artifact being attested
type ArtifactType string

const (
	ArtifactTypeBlob           ArtifactType = "blob"
	ArtifactTypeContainerImage ArtifactType = "container-image"
)

// Statement represents the base statement type for all attestations
type Statement struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subject       []Subject `json:"subject"`
}

// Subject represents a subject in an attestation
type Subject struct {
	Name   string `json:"name"`
	Digest struct {
		SHA256 string `json:"sha256"`
	} `json:"digest"`
}

type Metadata struct {
	Statement
	Predicate struct {
		Artifact struct {
			Version  string `json:"version"`
			Created  string `json:"created"`
			Type     string `json:"type"`
			Registry string `json:"registry,omitempty"`
			FullName string `json:"fullName,omitempty"`
			Digest   string `json:"digest,omitempty"`
			Path     string `json:"path,omitempty"`
		} `json:"artifact"`
		RepositoryData struct {
			Repository      string `json:"repository"`
			RepositoryId    string `json:"repositoryId"`
			GitHubServerURL string `json:"githubServerURL"`
		} `json:"repositoryData"`
		OwnerData struct {
			Owner   string `json:"owner"`
			OwnerId string `json:"ownerId"`
		} `json:"ownerData"`
		RunnerData struct {
			OS          string `json:"os"`
			Arch        string `json:"arch"`
			Environment string `json:"environment"`
		} `json:"runnerData"`
		WorkflowData struct {
			WorkflowRefPath string         `json:"workflowRefPath"`
			Inputs          map[string]any `json:"inputs"`
			Branch          string         `json:"branch"`
			Event           string         `json:"event"`
		} `json:"workflowData"`
		JobData struct {
			RunNumber   string `json:"runNumber"`
			RunId       string `json:"runId"`
			Status      string `json:"status"`
			TriggeredBy string `json:"triggeredBy"`
			StartedAt   string `json:"startedAt"`
			CompletedAt string `json:"completedAt"`
		} `json:"jobData"`
		CommitData struct {
			SHA       string `json:"sha"`
			Timestamp string `json:"timestamp"`
		} `json:"commitData"`
		Organization struct {
			Name string `json:"name"`
		} `json:"organization"`
		Compliance struct {
			PolicyRef  string   `json:"policyRef"`
			ControlIds []string `json:"controlIds"`
		} `json:"compliance"`
		Security struct {
			Permissions struct {
				IdToken      string `json:"id-token"`
				Attestations string `json:"attestations"`
				Contents     string `json:"contents"`
				Packages     string `json:"packages"`
			} `json:"permissions"`
		} `json:"security"`
	} `json:"predicate"`
}

type Options struct {
	// Subject details
	SubjectName string
	SubjectPath string
	Digest      string

	// Artifact details
	Version  string
	Created  time.Time
	Type     ArtifactType
	Registry string // only for container images
	FullName string // only for container images
	Path     string // only for blobs

	// Repository details
	Repository      string
	RepositoryID    string
	GitHubServerURL string

	// Owner details
	Owner   string
	OwnerID string

	// Runner details
	OS          string
	Arch        string
	Environment string

	// Build details
	BuildType      string
	PermissionType string

	// Workflow details
	WorkflowRefPath string
	Inputs          map[string]any
	Branch          string
	Event           string

	// Job details
	RunNumber   string
	RunID       string
	Status      string
	TriggeredBy string
	StartedAt   time.Time
	CompletedAt time.Time

	// Organization details
	Organization string

	// Commit details
	SHA string
}

func (m *Metadata) Type() string {
	return PredicateTypeURI
}

func (m *Metadata) Generate() ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := validation.ValidateMetadata(data); err != nil {
		return nil, err
	}

	return data, nil
}

func NewFromOptions(opts Options) (*Metadata, error) {
	m := &Metadata{
		Statement: Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: PredicateTypeURI,
			Subject: []Subject{
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

	// Set artifact data
	m.Predicate.Artifact.Version = opts.Version
	m.Predicate.Artifact.Created = opts.Created.Format(time.RFC3339)
	m.Predicate.Artifact.Type = string(opts.Type)

	switch opts.Type {
	case ArtifactTypeContainerImage:
		m.Predicate.Artifact.Registry = opts.Registry
		m.Predicate.Artifact.FullName = opts.FullName
		m.Predicate.Artifact.Digest = opts.Digest
	case ArtifactTypeBlob:
		m.Predicate.Artifact.Path = opts.Path
	}

	// Set repository data
	m.Predicate.RepositoryData.Repository = opts.Repository
	m.Predicate.RepositoryData.RepositoryId = opts.RepositoryID
	m.Predicate.RepositoryData.GitHubServerURL = opts.GitHubServerURL

	// Set owner data
	m.Predicate.OwnerData.Owner = opts.Owner
	m.Predicate.OwnerData.OwnerId = opts.OwnerID

	// Set runner data
	m.Predicate.RunnerData.OS = opts.OS
	m.Predicate.RunnerData.Arch = opts.Arch
	m.Predicate.RunnerData.Environment = opts.Environment

	// Set workflow data
	m.Predicate.WorkflowData.WorkflowRefPath = opts.WorkflowRefPath
	m.Predicate.WorkflowData.Inputs = opts.Inputs
	m.Predicate.WorkflowData.Branch = opts.Branch
	m.Predicate.WorkflowData.Event = opts.Event

	// Set job data
	m.Predicate.JobData.RunNumber = opts.RunNumber
	m.Predicate.JobData.RunId = opts.RunID
	m.Predicate.JobData.Status = opts.Status
	m.Predicate.JobData.TriggeredBy = opts.TriggeredBy
	m.Predicate.JobData.StartedAt = opts.StartedAt.Format(time.RFC3339)
	m.Predicate.JobData.CompletedAt = opts.CompletedAt.Format(time.RFC3339)

	// Set commit data
	m.Predicate.CommitData.SHA = opts.SHA
	m.Predicate.CommitData.Timestamp = opts.Created.Format(time.RFC3339)

	// Set organization data
	m.Predicate.Organization.Name = opts.Organization

	// Set compliance data
	m.Predicate.Compliance.PolicyRef = "https://github.com/liatrio/demo-gh-autogov-policy-library"
	m.Predicate.Compliance.ControlIds = []string{"test-control"}

	// Set security data
	m.Predicate.Security.Permissions.IdToken = "write"
	m.Predicate.Security.Permissions.Attestations = "write"
	m.Predicate.Security.Permissions.Contents = "read"
	m.Predicate.Security.Permissions.Packages = "read"

	return m, nil
}
