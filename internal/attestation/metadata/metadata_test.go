package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewFromOptions(t *testing.T) {
	t.Run("blob", func(t *testing.T) {
		now := time.Now()
		opts := Options{
			// Subject details
			SubjectName: "test-subject",
			SubjectPath: "test-path",
			Digest:      "test-digest",

			// Artifact details
			Version: "1.0.0",
			Created: now,
			Type:    ArtifactTypeBlob,

			// Repository details
			Repository:      "test-repo",
			GitHubServerURL: "test-server-url",

			// Owner details
			Owner: "test-owner",

			// Runner details
			OS:   "test-os",
			Name: "test-runner",

			// Build details
			BuildType:      "github-workflow",
			PermissionType: "github-workflow",

			// Workflow details
			WorkflowName:    "test-workflow",
			WorkflowRefPath: "test-workflow-ref",
			RunID:           "test-run-id",

			// Job details
			JobName: "test-job",

			// Commit details
			SHA:     "test-sha",
			Message: "test-message",
			Author:  "test-author",
			URL:     "test-url",
		}

		m, err := NewFromOptions(opts)
		assert.NoError(t, err)
		assert.NotNil(t, m)

		// Verify Artifact fields
		assert.Equal(t, opts.Version, m.Artifact.Version)
		assert.Equal(t, opts.Created.Format(time.RFC3339), m.Artifact.Created)
		assert.Equal(t, string(opts.Type), m.Artifact.Type)
		assert.Equal(t, opts.SubjectPath, m.Artifact.Path)
		assert.Equal(t, opts.Digest, m.Artifact.Digest)
		assert.Empty(t, m.Artifact.Registry)
		assert.Empty(t, m.Artifact.FullName)

		verifyCommonFields(t, opts, m)
	})

	t.Run("container_image", func(t *testing.T) {
		now := time.Now()
		opts := Options{
			// Subject details
			SubjectName: "test-subject",
			Digest:      "test-digest",

			// Artifact details
			Version:  "1.0.0",
			Created:  now,
			Type:     ArtifactTypeContainerImage,
			Registry: "test-registry",
			FullName: "test-fullname",

			// Repository details
			Repository:      "test-repo",
			GitHubServerURL: "test-server-url",

			// Owner details
			Owner: "test-owner",

			// Runner details
			OS:   "test-os",
			Name: "test-runner",

			// Build details
			BuildType:      "github-workflow",
			PermissionType: "github-workflow",

			// Workflow details
			WorkflowName:    "test-workflow",
			WorkflowRefPath: "test-workflow-ref",
			RunID:           "test-run-id",

			// Job details
			JobName: "test-job",

			// Commit details
			SHA:     "test-sha",
			Message: "test-message",
			Author:  "test-author",
			URL:     "test-url",
		}

		m, err := NewFromOptions(opts)
		assert.NoError(t, err)
		assert.NotNil(t, m)

		// Verify Artifact fields
		assert.Equal(t, opts.Version, m.Artifact.Version)
		assert.Equal(t, opts.Created.Format(time.RFC3339), m.Artifact.Created)
		assert.Equal(t, string(opts.Type), m.Artifact.Type)
		assert.Equal(t, opts.Registry, m.Artifact.Registry)
		assert.Equal(t, opts.FullName, m.Artifact.FullName)
		assert.Equal(t, opts.Digest, m.Artifact.Digest)
		assert.Empty(t, m.Artifact.Path)

		verifyCommonFields(t, opts, m)
	})
}

func verifyCommonFields(t *testing.T, opts Options, m *Metadata) {
	// Verify metadata fields
	assert.Equal(t, opts.BuildType, m.Metadata.BuildType)
	assert.Equal(t, opts.PermissionType, m.Metadata.PermissionType)

	// Verify repository data
	assert.Equal(t, opts.Repository, m.Metadata.Repository.Name)
	assert.Equal(t, opts.Owner, m.Metadata.Repository.Owner)
	assert.Equal(t, opts.GitHubServerURL, m.Metadata.Repository.URL)

	// Verify workflow data
	assert.Equal(t, opts.WorkflowName, m.Metadata.Workflow.Name)
	assert.Equal(t, opts.WorkflowRefPath, m.Metadata.Workflow.Ref)
	assert.Equal(t, opts.RunID, m.Metadata.Workflow.ID)

	// Verify job data
	assert.Equal(t, opts.JobName, m.Metadata.Job.Name)
	assert.Equal(t, opts.RunID, m.Metadata.Job.ID)

	// Verify runner data
	assert.Equal(t, opts.Name, m.Metadata.Runner.Name)
	assert.Equal(t, opts.OS, m.Metadata.Runner.OS)

	// Verify commit data
	assert.Equal(t, opts.SHA, m.Metadata.Commit.SHA)
	assert.Equal(t, opts.Message, m.Metadata.Commit.Message)
	assert.Equal(t, opts.Author, m.Metadata.Commit.Author)
	assert.Equal(t, opts.URL, m.Metadata.Commit.URL)
}
