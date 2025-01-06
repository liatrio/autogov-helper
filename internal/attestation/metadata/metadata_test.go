package metadata

import (
	"encoding/json"
	"testing"
	"time"

	"gh-attest-util/internal/github"

	"github.com/stretchr/testify/assert"
)

func TestNewFromGitHubContext(t *testing.T) {
	// Setup test data
	ctx := &github.Context{
		Repository:        "test-repo",
		RepositoryOwner:   "test-owner",
		RepositoryID:      "123",
		ServerURL:         "https://github.com",
		RepositoryOwnerID: "456",
		WorkflowRef:       "main",
		RefName:           "main",
		EventName:         "push",
		SHA:               "abc1234567",
		RunNumber:         "1",
		RunID:             "789",
		Actor:             "test-user",
	}
	ctx.Event.WorkflowRun.CreatedAt = "2024-03-14T12:00:00Z"
	ctx.Event.HeadCommit.Timestamp = "2024-03-14T12:00:00Z"

	runner := &github.Runner{
		OS:          "Linux",
		Arch:        "X64",
		Environment: "github-hosted",
	}

	opts := Options{
		SubjectName: "test-image",
		Digest:      "sha256:123",
		Registry:    "ghcr.io",
		JobStatus:   "success",
		PolicyRef:   "https://example.com/policy",
		ControlIds:  []string{"TEST-001", "TEST-002"},
	}

	// Test metadata generation
	t.Run("generates valid metadata", func(t *testing.T) {
		m, err := NewFromGitHubContext(ctx, runner, opts)
		assert.NoError(t, err)

		// Test metadata generation
		data, err := m.Generate()
		assert.NoError(t, err)

		// Verify JSON structure
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		assert.NoError(t, err)

		// Verify key sections
		assert.Contains(t, result, "artifact")
		assert.Contains(t, result, "repositoryData")
		assert.Contains(t, result, "ownerData")
		assert.Contains(t, result, "runnerData")
		assert.Contains(t, result, "workflowData")
		assert.Contains(t, result, "jobData")
		assert.Contains(t, result, "commitData")
		assert.Contains(t, result, "organization")
		assert.Contains(t, result, "compliance")
		assert.Contains(t, result, "security")

		// Verify specific values
		artifact := result["artifact"].(map[string]interface{})
		assert.Equal(t, "abc1234-1", artifact["version"])
		assert.Equal(t, "sha256:123", artifact["digest"])
		assert.Equal(t, "container-image", artifact["type"])
		assert.Equal(t, "ghcr.io", artifact["registry"])
		assert.Equal(t, "test-image", artifact["fullName"])

		// Verify timestamps are valid
		_, err = time.Parse(time.RFC3339, artifact["created"].(string))
		assert.NoError(t, err)
	})
}

func TestMetadataType(t *testing.T) {
	m := &Metadata{}
	assert.Equal(t, PredicateTypeURI, m.Type())
}
