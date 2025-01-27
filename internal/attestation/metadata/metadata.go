package metadata

import (
	"encoding/json"
	"time"

	schema "gh-attest-util/internal/attestation/generated"
	"gh-attest-util/internal/github"
)

const PredicateTypeURI = "https://cosign.sigstore.dev/attestation/v1"

type Metadata struct {
	schema.Statement
	Predicate schema.MetadataPredicate `json:"predicate"`
}

type MetadataPredicate struct {
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
		RepositoryID    string `json:"repositoryId"`
		GitHubServerURL string `json:"githubServerURL"`
	} `json:"repositoryData"`
	OwnerData struct {
		Owner   string `json:"owner"`
		OwnerID string `json:"ownerId"`
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
		RunID       string `json:"runId"`
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
		ControlIDs []string `json:"controlIds"`
	} `json:"compliance"`
	Security struct {
		Permissions schema.Permissions `json:"permissions"`
	} `json:"security"`
}

// ArtifactType represents the type of artifact being attested
type ArtifactType string

const (
	ArtifactTypeBlob           ArtifactType = "blob"
	ArtifactTypeContainerImage ArtifactType = "container-image"
)

// Options represents the configuration for generating metadata
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

	// Commit details
	SHA       string
	Timestamp time.Time

	// Organization details
	Organization string

	// Compliance details
	PolicyRef  string
	ControlIds []string

	// Security details
	Permissions map[string]string
}

func (m *Metadata) Type() string {
	return PredicateTypeURI
}

func (m *Metadata) Generate() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func NewFromOptions(opts Options) (*Metadata, error) {
	m := &Metadata{
		Statement: schema.Statement{
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

	// Set artifact data based on type
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
	m.Predicate.RepositoryData.GithubServerURL = opts.GitHubServerURL

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
	m.Predicate.CommitData.Timestamp = opts.Timestamp.Format(time.RFC3339)

	// Set organization data
	m.Predicate.Organization.Name = opts.Organization

	// Set compliance data
	m.Predicate.Compliance.PolicyRef = opts.PolicyRef
	m.Predicate.Compliance.ControlIds = opts.ControlIds

	// Set security data
	m.Predicate.Security.Permissions = schema.Permissions{
		IdToken:      opts.Permissions["id-token"],
		Attestations: opts.Permissions["attestations"],
		Contents:     opts.Permissions["contents"],
		Packages:     opts.Permissions["packages"],
	}

	return m, nil
}

func New(ctx *github.Context) (*Metadata, error) {
	m := &Metadata{
		Statement: schema.Statement{
			Type:          "_type",
			PredicateType: "https://in-toto.io/attestation/github-workflow/v0.2",
			Subject:       []schema.Subject{},
		},
	}

	// Set artifact data
	m.Predicate.Artifact.Created = time.Now().UTC().Format(time.RFC3339)
	m.Predicate.Artifact.Type = "https://in-toto.io/attestation/github-workflow/v0.2"
	m.Predicate.Artifact.Version = "1.0"

	// Set repository data
	m.Predicate.RepositoryData.Repository = ctx.Repository
	m.Predicate.RepositoryData.RepositoryId = ctx.RepositoryID
	m.Predicate.RepositoryData.GithubServerURL = ctx.ServerURL

	// Set owner data
	m.Predicate.OwnerData.Owner = ctx.RepositoryOwner
	m.Predicate.OwnerData.OwnerId = ctx.RepositoryOwnerID

	// Set runner data
	m.Predicate.RunnerData.Environment = ctx.Runner.Environment
	m.Predicate.RunnerData.OS = ctx.Runner.OS
	m.Predicate.RunnerData.Arch = ctx.Runner.Arch

	// Set workflow data
	m.Predicate.WorkflowData.Event = ctx.EventName
	m.Predicate.WorkflowData.WorkflowRefPath = ctx.WorkflowRef
	m.Predicate.WorkflowData.Inputs = ctx.Inputs
	m.Predicate.WorkflowData.Branch = ctx.RefName

	// Set job data
	m.Predicate.JobData.RunNumber = ctx.RunNumber
	m.Predicate.JobData.RunId = ctx.RunID
	m.Predicate.JobData.Status = ctx.JobStatus
	m.Predicate.JobData.TriggeredBy = ctx.Actor
	m.Predicate.JobData.StartedAt = ctx.Event.WorkflowRun.CreatedAt
	m.Predicate.JobData.CompletedAt = time.Now().UTC().Format(time.RFC3339)

	// Set commit data
	m.Predicate.CommitData.Timestamp = ctx.Event.HeadCommit.Timestamp
	m.Predicate.CommitData.SHA = ctx.SHA

	// Set organization data
	m.Predicate.Organization.Name = ctx.RepositoryOwner

	// Set compliance data
	m.Predicate.Compliance.PolicyRef = ""
	m.Predicate.Compliance.ControlIds = []string{}

	// Set security data
	m.Predicate.Security.Permissions = schema.Permissions{
		IdToken:      "",
		Attestations: "",
		Contents:     "",
		Packages:     "",
	}

	return m, nil
}
