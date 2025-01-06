package metadata

import (
	"encoding/json"
	"fmt"
	"time"

	"gh-attest-util/internal/github"
)

const PredicateTypeURI = "https://cosign.sigstore.dev/attestation/v1"

type Metadata struct {
	Artifact struct {
		Version  string    `json:"version"`
		Digest   string    `json:"digest"`
		Created  time.Time `json:"created"`
		Type     string    `json:"type"`
		Registry string    `json:"registry"`
		FullName string    `json:"fullName"`
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
		RunNumber   string    `json:"runNumber"`
		RunID       string    `json:"runId"`
		Status      string    `json:"status"`
		TriggeredBy string    `json:"triggeredBy"`
		StartedAt   time.Time `json:"startedAt"`
		CompletedAt time.Time `json:"completedAt"`
	} `json:"jobData"`

	CommitData struct {
		SHA       string    `json:"sha"`
		Timestamp time.Time `json:"timestamp"`
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

func (m *Metadata) Type() string {
	return PredicateTypeURI
}

func (m *Metadata) Generate() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// NewFromGitHubContext creates a new Metadata instance from GitHub context
func NewFromGitHubContext(ctx *github.Context, runner *github.Runner, opts Options) (*Metadata, error) {
	now := time.Now().UTC()

	// Make SHA slicing safe
	shortSHA := ctx.SHA
	if len(ctx.SHA) >= 7 {
		shortSHA = ctx.SHA[:7]
	}
	version := fmt.Sprintf("%s-%s", shortSHA, ctx.RunNumber)

	m := &Metadata{}

	// Artifact info
	m.Artifact.Version = version
	m.Artifact.Digest = opts.Digest
	m.Artifact.Created = now
	m.Artifact.Type = "container-image"
	m.Artifact.Registry = opts.Registry
	m.Artifact.FullName = opts.SubjectName

	// Repository data
	m.RepositoryData.Repository = ctx.Repository
	m.RepositoryData.RepositoryID = ctx.RepositoryID
	m.RepositoryData.GitHubServerURL = ctx.ServerURL

	// Owner data
	m.OwnerData.Owner = ctx.RepositoryOwner
	m.OwnerData.OwnerID = ctx.OwnerID

	// Runner data
	m.RunnerData.OS = runner.OS
	m.RunnerData.Arch = runner.Arch
	m.RunnerData.Environment = runner.Environment

	// Workflow data
	m.WorkflowData.WorkflowRefPath = ctx.WorkflowRef
	m.WorkflowData.Inputs = ctx.Inputs
	m.WorkflowData.Branch = ctx.RefName
	m.WorkflowData.Event = ctx.EventName

	// Job data
	m.JobData.RunNumber = ctx.RunNumber
	m.JobData.RunID = ctx.RunID
	m.JobData.Status = opts.JobStatus
	m.JobData.TriggeredBy = ctx.Actor
	if startTime, err := time.Parse(time.RFC3339, ctx.Event.WorkflowRun.CreatedAt); err == nil {
		m.JobData.StartedAt = startTime
	}
	m.JobData.CompletedAt = now

	// Commit data
	m.CommitData.SHA = ctx.SHA
	if commitTime, err := time.Parse(time.RFC3339, ctx.Event.HeadCommit.Timestamp); err == nil {
		m.CommitData.Timestamp = commitTime
	}

	// Organization
	m.Organization.Name = ctx.RepositoryOwner

	// Compliance
	m.Compliance.PolicyRef = "https://github.com/liatrio/demo-gh-autogov-policy-library"
	if opts.PolicyRef != "" {
		m.Compliance.PolicyRef = opts.PolicyRef
	}
	if len(opts.ControlIds) == 0 {
		m.Compliance.ControlIds = []string{
			fmt.Sprintf("%s-PROVENANCE-001", ctx.RepositoryOwner),
			fmt.Sprintf("%s-SBOM-002", ctx.RepositoryOwner),
			fmt.Sprintf("%s-METADATA-003", ctx.RepositoryOwner),
		}
	} else {
		m.Compliance.ControlIds = opts.ControlIds
	}

	// Security
	m.Security.Permissions = map[string]string{
		"id-token":     "write",
		"attestations": "write",
		"packages":     "write",
		"contents":     "read",
	}

	return m, nil
}

type Options struct {
	SubjectName string
	Digest      string
	Registry    string
	JobStatus   string
	PolicyRef   string
	ControlIds  []string
}
