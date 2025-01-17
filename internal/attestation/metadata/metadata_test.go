package metadata

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFromOptions(t *testing.T) {
	now := time.Now().UTC()

	opts := Options{
		SubjectName:     "test-subject",
		Digest:          "sha256:abc123",
		Version:         "v1.0.0",
		Created:         now,
		Type:            "container-image",
		Registry:        "ghcr.io",
		FullName:        "test-subject:v1.0.0",
		Repository:      "owner/repo",
		RepositoryID:    "12345",
		GitHubServerURL: "https://github.com",
		Owner:           "owner",
		OwnerID:         "67890",
		OS:              "linux",
		Arch:            "amd64",
		Environment:     "github-hosted",
		WorkflowRefPath: ".github/workflows/build.yml",
		Inputs:          map[string]any{"foo": "bar"},
		Branch:          "main",
		Event:           "push",
		RunNumber:       "1",
		RunID:           "123456789",
		Status:          "success",
		TriggeredBy:     "user",
		StartedAt:       now.Add(-time.Hour),
		CompletedAt:     now,
		SHA:             "abcdef123456",
		Timestamp:       now.Add(-time.Hour),
		Organization:    "owner",
		PolicyRef:       "https://github.com/owner/policy",
		ControlIds:      []string{"CONTROL-001"},
		Permissions:     map[string]string{"id-token": "write"},
	}

	m, err := NewFromOptions(opts)
	require.NoError(t, err)

	assert.Equal(t, PredicateTypeURI, m.Type())
	assert.Equal(t, "test-subject", m.Subject[0].Name)
	assert.Equal(t, "sha256:abc123", m.Subject[0].Digest.SHA256)

	assert.Equal(t, "v1.0.0", m.Predicate.Artifact.Version)
	assert.Equal(t, now, m.Predicate.Artifact.Created)
	assert.Equal(t, "container-image", m.Predicate.Artifact.Type)
	assert.Equal(t, "ghcr.io", m.Predicate.Artifact.Registry)
	assert.Equal(t, "test-subject:v1.0.0", m.Predicate.Artifact.FullName)
	assert.Equal(t, "sha256:abc123", m.Predicate.Artifact.Digest)

	assert.Equal(t, "owner/repo", m.Predicate.RepositoryData.Repository)
	assert.Equal(t, "12345", m.Predicate.RepositoryData.RepositoryID)
	assert.Equal(t, "https://github.com", m.Predicate.RepositoryData.GitHubServerURL)

	assert.Equal(t, "owner", m.Predicate.OwnerData.Owner)
	assert.Equal(t, "67890", m.Predicate.OwnerData.OwnerID)

	assert.Equal(t, "linux", m.Predicate.RunnerData.OS)
	assert.Equal(t, "amd64", m.Predicate.RunnerData.Arch)
	assert.Equal(t, "github-hosted", m.Predicate.RunnerData.Environment)

	assert.Equal(t, ".github/workflows/build.yml", m.Predicate.WorkflowData.WorkflowRefPath)
	assert.Equal(t, map[string]any{"foo": "bar"}, m.Predicate.WorkflowData.Inputs)
	assert.Equal(t, "main", m.Predicate.WorkflowData.Branch)
	assert.Equal(t, "push", m.Predicate.WorkflowData.Event)

	assert.Equal(t, "1", m.Predicate.JobData.RunNumber)
	assert.Equal(t, "123456789", m.Predicate.JobData.RunID)
	assert.Equal(t, "success", m.Predicate.JobData.Status)
	assert.Equal(t, "user", m.Predicate.JobData.TriggeredBy)
	assert.Equal(t, now.Add(-time.Hour), m.Predicate.JobData.StartedAt)
	assert.Equal(t, now, m.Predicate.JobData.CompletedAt)

	assert.Equal(t, "abcdef123456", m.Predicate.CommitData.SHA)
	assert.Equal(t, now.Add(-time.Hour), m.Predicate.CommitData.Timestamp)

	assert.Equal(t, "owner", m.Predicate.Organization.Name)

	assert.Equal(t, "https://github.com/owner/policy", m.Predicate.Compliance.PolicyRef)
	assert.Equal(t, []string{"CONTROL-001"}, m.Predicate.Compliance.ControlIds)

	assert.Equal(t, map[string]string{"id-token": "write"}, m.Predicate.Security.Permissions)

	data, err := m.Generate()
	require.NoError(t, err)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(data, &jsonMap)
	require.NoError(t, err)

	assert.Equal(t, PredicateTypeURI, jsonMap["predicateType"])
}

func TestMetadataType(t *testing.T) {
	m := &Metadata{}
	assert.Equal(t, PredicateTypeURI, m.Type())
}
