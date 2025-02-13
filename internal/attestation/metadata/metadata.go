package metadata

import (
	"encoding/json"
	"time"
)

const PredicateTypeURI = "https://cosign.sigstore.dev/attestation/v1"

// represents the type of artifact being attested
type ArtifactType string

const (
	ArtifactTypeBlob           ArtifactType = "blob"
	ArtifactTypeContainerImage ArtifactType = "container-image"
)

// struct represents just the predicate portion of the attestation
type Metadata struct {
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
		Inputs          map[string]any `json:"inputs,omitempty"`
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
		ControlIds []string `json:"controlIds"`
	} `json:"compliance"`
	Security struct {
		Permissions map[string]string `json:"permissions"`
	} `json:"security"`
}

type Options struct {
	// artifact fields
	Version     string
	Created     time.Time
	Type        ArtifactType
	Registry    string
	FullName    string
	SubjectPath string
	Digest      string

	// repo fields
	Repository      string
	RepositoryID    string
	GitHubServerURL string

	// owner fields
	Owner   string
	OwnerID string

	// runner fields
	OS          string
	Arch        string
	Environment string

	// wf fields
	WorkflowRefPath string
	Inputs          map[string]any
	Branch          string
	Event           string

	// job fields
	RunNumber   string
	RunID       string
	Status      string
	TriggeredBy string
	StartedAt   time.Time
	CompletedAt time.Time

	// commit fields
	SHA       string
	Timestamp time.Time

	// org fields
	OrgName string

	// compliance fields
	PolicyRef  string
	ControlIds []string

	// permissions fields
	Permissions map[string]string
}

func (m *Metadata) Generate() ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return data, nil
}

func NewFromOptions(opts Options) (*Metadata, error) {
	m := &Metadata{}

	// set artifact fields
	m.Artifact.Version = opts.Version
	m.Artifact.Created = opts.Created.Format(time.RFC3339)
	m.Artifact.Type = string(opts.Type)

	switch opts.Type {
	case ArtifactTypeContainerImage:
		m.Artifact.Registry = opts.Registry
		m.Artifact.FullName = opts.FullName
		m.Artifact.Digest = opts.Digest
	case ArtifactTypeBlob:
		m.Artifact.Path = opts.SubjectPath
		m.Artifact.Digest = opts.Digest
	}

	// set repo data
	m.RepositoryData.Repository = opts.Repository
	m.RepositoryData.RepositoryID = opts.RepositoryID
	m.RepositoryData.GitHubServerURL = opts.GitHubServerURL

	// set owner data
	m.OwnerData.Owner = opts.Owner
	m.OwnerData.OwnerID = opts.OwnerID

	// set runner data
	m.RunnerData.OS = opts.OS
	m.RunnerData.Arch = opts.Arch
	m.RunnerData.Environment = opts.Environment

	// set wf data
	m.WorkflowData.WorkflowRefPath = opts.WorkflowRefPath
	m.WorkflowData.Branch = opts.Branch
	m.WorkflowData.Event = opts.Event

	// set job data
	m.JobData.RunNumber = opts.RunNumber
	m.JobData.RunID = opts.RunID
	m.JobData.Status = opts.Status
	m.JobData.TriggeredBy = opts.TriggeredBy
	m.JobData.StartedAt = opts.StartedAt.Format(time.RFC3339)
	m.JobData.CompletedAt = opts.CompletedAt.Format(time.RFC3339)

	// set commit data
	m.CommitData.SHA = opts.SHA
	m.CommitData.Timestamp = opts.Timestamp.Format(time.RFC3339)

	// set org data
	m.Organization.Name = opts.OrgName

	// set compliance data
	m.Compliance.PolicyRef = opts.PolicyRef
	m.Compliance.ControlIds = opts.ControlIds

	// set permissions data
	m.Security.Permissions = opts.Permissions

	// set workflow inputs if they exist
	if opts.Inputs != nil {
		m.WorkflowData.Inputs = opts.Inputs
	} else {
		m.WorkflowData.Inputs = make(map[string]any)
	}

	return m, nil
}
