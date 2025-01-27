package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewFromOptions(t *testing.T) {
	opts := Options{
		SubjectName:     "test-subject",
		SubjectPath:     "test-path",
		Digest:          "test-digest",
		Version:         "1.0.0",
		Created:         time.Now(),
		Type:            ArtifactTypeBlob,
		Path:            "test-path",
		Repository:      "test-repo",
		RepositoryID:    "test-repo-id",
		GitHubServerURL: "test-server-url",
		Owner:           "test-owner",
		OwnerID:         "test-owner-id",
		OS:              "test-os",
		Arch:            "test-arch",
		Environment:     "test-env",
		WorkflowRefPath: "test-workflow-ref",
		Inputs:          map[string]any{"test": "value"},
		Branch:          "test-branch",
		Event:           "test-event",
		RunNumber:       "test-run-number",
		RunID:           "test-run-id",
		Status:          "test-status",
		TriggeredBy:     "test-user",
		StartedAt:       time.Now(),
		CompletedAt:     time.Now(),
		SHA:             "test-sha",
		Timestamp:       time.Now(),
		Organization:    "test-org",
		PolicyRef:       "test-policy",
		ControlIds:      []string{"test-control"},
		Permissions: map[string]string{
			"id-token":     "write",
			"attestations": "write",
			"contents":     "read",
			"packages":     "read",
		},
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

	assert.Equal(t, opts.Repository, m.Predicate.RepositoryData.Repository)
	assert.Equal(t, opts.RepositoryID, m.Predicate.RepositoryData.RepositoryId)
	assert.Equal(t, opts.GitHubServerURL, m.Predicate.RepositoryData.GithubServerURL)

	assert.Equal(t, opts.Owner, m.Predicate.OwnerData.Owner)
	assert.Equal(t, opts.OwnerID, m.Predicate.OwnerData.OwnerId)

	assert.Equal(t, opts.OS, m.Predicate.RunnerData.OS)
	assert.Equal(t, opts.Arch, m.Predicate.RunnerData.Arch)
	assert.Equal(t, opts.Environment, m.Predicate.RunnerData.Environment)

	assert.Equal(t, opts.WorkflowRefPath, m.Predicate.WorkflowData.WorkflowRefPath)
	assert.Equal(t, map[string]any(m.Predicate.WorkflowData.Inputs), opts.Inputs)
	assert.Equal(t, opts.Branch, m.Predicate.WorkflowData.Branch)
	assert.Equal(t, opts.Event, m.Predicate.WorkflowData.Event)

	assert.Equal(t, opts.RunNumber, m.Predicate.JobData.RunNumber)
	assert.Equal(t, opts.RunID, m.Predicate.JobData.RunId)
	assert.Equal(t, opts.Status, m.Predicate.JobData.Status)
	assert.Equal(t, opts.TriggeredBy, m.Predicate.JobData.TriggeredBy)
	assert.Equal(t, opts.StartedAt.Format(time.RFC3339), m.Predicate.JobData.StartedAt)
	assert.Equal(t, opts.CompletedAt.Format(time.RFC3339), m.Predicate.JobData.CompletedAt)

	assert.Equal(t, opts.SHA, m.Predicate.CommitData.SHA)
	assert.Equal(t, opts.Timestamp.Format(time.RFC3339), m.Predicate.CommitData.Timestamp)

	assert.Equal(t, opts.Organization, m.Predicate.Organization.Name)

	assert.Equal(t, opts.PolicyRef, m.Predicate.Compliance.PolicyRef)
	assert.Equal(t, opts.ControlIds, m.Predicate.Compliance.ControlIds)

	assert.Equal(t, opts.Permissions["id-token"], m.Predicate.Security.Permissions.IdToken)
	assert.Equal(t, opts.Permissions["attestations"], m.Predicate.Security.Permissions.Attestations)
	assert.Equal(t, opts.Permissions["contents"], m.Predicate.Security.Permissions.Contents)
	assert.Equal(t, opts.Permissions["packages"], m.Predicate.Security.Permissions.Packages)
}

func TestMetadataType(t *testing.T) {
	m := &Metadata{}
	assert.Equal(t, PredicateTypeURI, m.Type())
}
