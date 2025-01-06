package github

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFromEnv(t *testing.T) {
	// Test case 1: Missing GITHUB_CONTEXT
	t.Run("missing context", func(t *testing.T) {
		os.Unsetenv("GITHUB_CONTEXT")
		_, err := LoadFromEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "GITHUB_CONTEXT environment variable not set")
	})

	// Test case 2: Invalid JSON
	t.Run("invalid json", func(t *testing.T) {
		os.Setenv("GITHUB_CONTEXT", "invalid json")
		_, err := LoadFromEnv()
		assert.Error(t, err)
	})

	// Test case 3: Valid context
	t.Run("valid context", func(t *testing.T) {
		validJSON := `{
			"repository": "test-repo",
			"repository_owner": "test-owner",
			"repository_id": "123",
			"server_url": "https://github.com",
			"repository_owner_id": "456",
			"workflow_ref": "main",
			"ref_name": "main",
			"event_name": "push",
			"sha": "abc123",
			"run_number": "1",
			"run_id": "789",
			"actor": "test-user",
			"event": {
				"workflow_run": {
					"created_at": "2024-03-14T12:00:00Z"
				},
				"head_commit": {
					"timestamp": "2024-03-14T12:00:00Z"
				}
			},
			"inputs": {
				"test": "value"
			}
		}`
		os.Setenv("GITHUB_CONTEXT", validJSON)
		ctx, err := LoadFromEnv()
		assert.NoError(t, err)
		assert.Equal(t, "test-repo", ctx.Repository)
		assert.Equal(t, "test-owner", ctx.RepositoryOwner)
		assert.Equal(t, "123", ctx.RepositoryID)
		assert.Equal(t, "abc123", ctx.SHA)
	})
}

func TestLoadRunnerFromEnv(t *testing.T) {
	// Test case 1: Missing RUNNER_OS
	t.Run("missing runner os", func(t *testing.T) {
		os.Unsetenv("RUNNER_OS")
		_, err := LoadRunnerFromEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RUNNER_OS environment variable not set")
	})

	// Test case 2: Missing RUNNER_ARCH
	t.Run("missing runner arch", func(t *testing.T) {
		os.Setenv("RUNNER_OS", "Linux")
		os.Unsetenv("RUNNER_ARCH")
		_, err := LoadRunnerFromEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RUNNER_ARCH environment variable not set")
	})

	// Test case 3: Valid runner context
	t.Run("valid runner context", func(t *testing.T) {
		os.Setenv("RUNNER_OS", "Linux")
		os.Setenv("RUNNER_ARCH", "X64")
		os.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
		runner, err := LoadRunnerFromEnv()
		assert.NoError(t, err)
		assert.Equal(t, "Linux", runner.OS)
		assert.Equal(t, "X64", runner.Arch)
		assert.Equal(t, "github-hosted", runner.Environment)
	})
}
