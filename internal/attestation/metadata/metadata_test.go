package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewFromOptions(t *testing.T) {
	testCases := []struct {
		name           string
		artifactType   ArtifactType
		highPermission bool
		opts           Options
		expectedEmpty  []string
	}{
		{
			name:           "blob_high_permissions",
			artifactType:   ArtifactTypeBlob,
			highPermission: true,
			opts: Options{
				SubjectName:    "test-subject",
				SubjectPath:    "test-path",
				Digest:         "test-digest",
				Version:        "1.0.0",
				Type:           ArtifactTypeBlob,
				BuildType:      "github-workflow",
				PermissionType: "github-workflow",
			},
			expectedEmpty: []string{"registry", "fullName"},
		},
		{
			name:           "blob_low_permissions",
			artifactType:   ArtifactTypeBlob,
			highPermission: false,
			opts: Options{
				SubjectName:    "test-subject",
				SubjectPath:    "test-path",
				Digest:         "test-digest",
				Version:        "1.0.0",
				Type:           ArtifactTypeBlob,
				BuildType:      "github-workflow",
				PermissionType: "github-workflow",
			},
			expectedEmpty: []string{"registry", "fullName"},
		},
		{
			name:           "container_image_high_permissions",
			artifactType:   ArtifactTypeContainerImage,
			highPermission: true,
			opts: Options{
				SubjectName:    "test-subject",
				Digest:         "test-digest",
				Version:        "1.0.0",
				Type:           ArtifactTypeContainerImage,
				Registry:       "test-registry",
				FullName:       "test-registry/test-repo@test-digest",
				BuildType:      "github-workflow",
				PermissionType: "github-workflow",
			},
			expectedEmpty: []string{"path"},
		},
		{
			name:           "container_image_low_permissions",
			artifactType:   ArtifactTypeContainerImage,
			highPermission: false,
			opts: Options{
				SubjectName:    "test-subject",
				Digest:         "test-digest",
				Version:        "1.0.0",
				Type:           ArtifactTypeContainerImage,
				Registry:       "test-registry",
				FullName:       "test-registry/test-repo@test-digest",
				BuildType:      "github-workflow",
				PermissionType: "github-workflow",
			},
			expectedEmpty: []string{"path"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			opts := tc.opts
			opts.Created = now

			// Common fields
			opts.Repository = "test-repo"
			opts.GitHubServerURL = "test-server-url"
			opts.Owner = "test-owner"
			opts.OS = "test-os"
			opts.Name = "test-runner"
			opts.WorkflowName = "test-workflow"
			opts.WorkflowRefPath = "test-workflow-ref"
			opts.RunID = "test-run-id"
			opts.JobName = "test-job"
			opts.SHA = "test-sha"
			opts.Message = "test-message"
			opts.Author = "test-author"
			opts.URL = "test-url"

			m, err := NewFromOptions(opts)
			assert.NoError(t, err)
			assert.NotNil(t, m)

			// Verify Artifact fields
			assert.Equal(t, opts.Version, m.Artifact.Version)
			assert.Equal(t, opts.Created.Format(time.RFC3339), m.Artifact.Created)
			assert.Equal(t, string(opts.Type), m.Artifact.Type)
			assert.Equal(t, opts.Digest, m.Artifact.Digest)

			// Verify type-specific fields
			if tc.artifactType == ArtifactTypeBlob {
				assert.Equal(t, opts.SubjectPath, m.Artifact.Path)
				assert.Empty(t, m.Artifact.Registry)
				assert.Empty(t, m.Artifact.FullName)
			} else {
				assert.Equal(t, opts.Registry, m.Artifact.Registry)
				assert.Equal(t, opts.FullName, m.Artifact.FullName)
				assert.Empty(t, m.Artifact.Path)
			}

			verifyCommonFields(t, opts, m)
		})
	}
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
