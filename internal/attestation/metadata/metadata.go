package metadata

import (
	"encoding/json"
	"time"
)

const PredicateTypeURI = "https://cosign.sigstore.dev/attestation/v1"

// ArtifactType represents the type of artifact being attested
type ArtifactType string

const (
	ArtifactTypeBlob           ArtifactType = "blob"
	ArtifactTypeContainerImage ArtifactType = "container-image"
)

// Metadata struct matches predicates/metadata.json
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
	Metadata struct {
		BuildType      string `json:"buildType"`
		PermissionType string `json:"permissionType"`
		Repository     struct {
			Name  string `json:"name"`
			Owner string `json:"owner"`
			URL   string `json:"url"`
		} `json:"repository"`
		Workflow struct {
			Name string `json:"name"`
			Ref  string `json:"ref"`
			ID   string `json:"id"`
		} `json:"workflow"`
		Job struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"job"`
		Runner struct {
			Name string `json:"name"`
			OS   string `json:"os"`
		} `json:"runner"`
		Commit struct {
			SHA     string `json:"sha"`
			Message string `json:"message"`
			Author  string `json:"author"`
			URL     string `json:"url"`
		} `json:"commit"`
	} `json:"metadata"`
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
	GitHubServerURL string

	// Owner details
	Owner string

	// Runner details
	OS   string
	Name string

	// Build details
	BuildType      string
	PermissionType string

	// Workflow details
	WorkflowName    string
	WorkflowRefPath string
	RunID           string

	// Job details
	JobName string

	// Commit details
	SHA     string
	Message string
	Author  string
	URL     string
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

	// Set artifact data
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

	// Set metadata
	m.Metadata.BuildType = "github-workflow"
	m.Metadata.PermissionType = "github-workflow"

	// Set repository data
	m.Metadata.Repository.Name = opts.Repository
	m.Metadata.Repository.Owner = opts.Owner
	m.Metadata.Repository.URL = opts.GitHubServerURL

	// Set workflow data
	m.Metadata.Workflow.Name = opts.WorkflowName
	m.Metadata.Workflow.Ref = opts.WorkflowRefPath
	m.Metadata.Workflow.ID = opts.RunID

	// Set job data
	m.Metadata.Job.Name = opts.JobName
	m.Metadata.Job.ID = opts.RunID

	// Set runner data
	m.Metadata.Runner.Name = opts.Name
	m.Metadata.Runner.OS = opts.OS

	// Set commit data
	m.Metadata.Commit.SHA = opts.SHA
	m.Metadata.Commit.Message = opts.Message
	m.Metadata.Commit.Author = opts.Author
	m.Metadata.Commit.URL = opts.URL

	return m, nil
}
