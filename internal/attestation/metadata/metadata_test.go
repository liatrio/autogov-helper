package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewFromOptions(t *testing.T) {
	now := time.Now()
	opts := Options{
		// Subject details
		SubjectName: "test-subject",
		SubjectPath: "test-path",
		Digest:      "test-digest",

		// Artifact details
		Version:  "1.0.0",
		Created:  now,
		Type:     ArtifactTypeBlob,
		Registry: "test-registry",
		FullName: "test-fullname",
		Path:     "test-path",

		// Repository details
		Repository:      "test-repo",
		RepositoryID:    "test-repo-id",
		GitHubServerURL: "test-server-url",

		// Owner details
		Owner:   "test-owner",
		OwnerID: "test-owner-id",

		// Runner details
		OS:          "test-os",
		Arch:        "test-arch",
		Environment: "test-env",

		// Build details
		BuildType:      "test-build-type",
		PermissionType: "test-permission-type",

		// Workflow details
		WorkflowRefPath: "test-workflow-ref",
		Inputs:          map[string]any{"test": "value"},
		Branch:          "test-branch",
		Event:           "test-event",

		// Job details
		RunNumber:   "test-run-number",
		RunID:       "test-run-id",
		Status:      "test-status",
		TriggeredBy: "test-user",
		StartedAt:   now,
		CompletedAt: now,

		// Organization details
		Organization: "test-org",

		// Commit details
		SHA: "test-sha",
	}

	m, err := NewFromOptions(opts)
	assert.NoError(t, err)
	assert.NotNil(t, m)

	// Verify Statement fields
	assert.Equal(t, "https://in-toto.io/Statement/v1", m.Statement.Type)
	assert.Equal(t, PredicateTypeURI, m.Statement.PredicateType)
	assert.Equal(t, opts.SubjectName, m.Statement.Subject[0].Name)
	assert.Equal(t, opts.Digest, m.Statement.Subject[0].Digest.SHA256)

	// Verify Predicate fields
	assert.Equal(t, opts.Version, m.Predicate.Artifact.Version)
	assert.Equal(t, opts.Created.Format(time.RFC3339), m.Predicate.Artifact.Created)
	assert.Equal(t, string(opts.Type), m.Predicate.Artifact.Type)
	assert.Equal(t, opts.Path, m.Predicate.Artifact.Path)

	// Verify Repository data
	assert.Equal(t, opts.Repository, m.Predicate.RepositoryData.Repository)
	assert.Equal(t, opts.RepositoryID, m.Predicate.RepositoryData.RepositoryId)
	assert.Equal(t, opts.GitHubServerURL, m.Predicate.RepositoryData.GitHubServerURL)

	// Verify Owner data
	assert.Equal(t, opts.Owner, m.Predicate.OwnerData.Owner)
	assert.Equal(t, opts.OwnerID, m.Predicate.OwnerData.OwnerId)

	// Verify Runner data
	assert.Equal(t, opts.OS, m.Predicate.RunnerData.OS)
	assert.Equal(t, opts.Arch, m.Predicate.RunnerData.Arch)
	assert.Equal(t, opts.Environment, m.Predicate.RunnerData.Environment)

	// Verify Workflow data
	assert.Equal(t, opts.WorkflowRefPath, m.Predicate.WorkflowData.WorkflowRefPath)
	assert.Equal(t, opts.Inputs, m.Predicate.WorkflowData.Inputs)
	assert.Equal(t, opts.Branch, m.Predicate.WorkflowData.Branch)
	assert.Equal(t, opts.Event, m.Predicate.WorkflowData.Event)

	// Verify Job data
	assert.Equal(t, opts.RunNumber, m.Predicate.JobData.RunNumber)
	assert.Equal(t, opts.RunID, m.Predicate.JobData.RunId)
	assert.Equal(t, opts.Status, m.Predicate.JobData.Status)
	assert.Equal(t, opts.TriggeredBy, m.Predicate.JobData.TriggeredBy)
	assert.Equal(t, opts.StartedAt.Format(time.RFC3339), m.Predicate.JobData.StartedAt)
	assert.Equal(t, opts.CompletedAt.Format(time.RFC3339), m.Predicate.JobData.CompletedAt)

	// Verify Commit data
	assert.Equal(t, opts.SHA, m.Predicate.CommitData.SHA)
	assert.Equal(t, opts.Created.Format(time.RFC3339), m.Predicate.CommitData.Timestamp)

	// Verify Organization data
	assert.Equal(t, opts.Organization, m.Predicate.Organization.Name)

	// Verify Compliance data
	assert.Equal(t, "https://github.com/liatrio/demo-gh-autogov-policy-library", m.Predicate.Compliance.PolicyRef)
	assert.Equal(t, []string{"test-control"}, m.Predicate.Compliance.ControlIds)

	// Verify Security data
	assert.Equal(t, "write", m.Predicate.Security.Permissions.IdToken)
	assert.Equal(t, "write", m.Predicate.Security.Permissions.Attestations)
	assert.Equal(t, "read", m.Predicate.Security.Permissions.Contents)
	assert.Equal(t, "read", m.Predicate.Security.Permissions.Packages)
}

func TestMetadataType(t *testing.T) {
	m := &Metadata{}
	assert.Equal(t, PredicateTypeURI, m.Type())
}
