package github

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFromEnv(t *testing.T) {
	// Test case 1: Empty environment variables
	t.Run("empty environment", func(t *testing.T) {
		os.Clearenv()
		ctx, err := LoadFromEnv()
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.Empty(t, ctx.Repository)
		assert.Empty(t, ctx.RepositoryOwner)
	})

	// Test case 2: Valid environment variables
	t.Run("valid environment", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("GITHUB_REPOSITORY", "test-repo")
		os.Setenv("GITHUB_REPOSITORY_OWNER", "test-owner")
		os.Setenv("GITHUB_REPOSITORY_ID", "123")
		os.Setenv("GITHUB_SHA", "abc123")
		os.Setenv("INPUT_TEST", "value")

		ctx, err := LoadFromEnv()
		assert.NoError(t, err)
		assert.Equal(t, "test-repo", ctx.Repository)
		assert.Equal(t, "test-owner", ctx.RepositoryOwner)
		assert.Equal(t, "123", ctx.RepositoryID)
		assert.Equal(t, "abc123", ctx.SHA)
		assert.Equal(t, "value", ctx.Inputs["test"])
	})

	// Test case 3: Workflow inputs from JSON
	t.Run("workflow inputs from json", func(t *testing.T) {
		os.Clearenv()
		workflowInputs := `{
			"registry": "ghcr.io",
			"image": "test-image"
		}`
		eventData := `{
			"workflow_run": {
				"created_at": "2024-01-06T12:00:00Z"
			},
			"head_commit": {
				"timestamp": "2024-01-06T12:00:00Z"
			}
		}`

		// Create a temporary event file
		tmpDir := t.TempDir()
		eventPath := filepath.Join(tmpDir, "event.json")
		err := os.WriteFile(eventPath, []byte(eventData), 0644)
		assert.NoError(t, err)

		os.Setenv("GITHUB_EVENT_PATH", eventPath)
		os.Setenv("GITHUB_WORKFLOW_INPUTS", workflowInputs)
		os.Setenv("INPUT_EXTRA", "extra-value")

		ctx, err := LoadFromEnv()
		assert.NoError(t, err)
		assert.Equal(t, "ghcr.io", ctx.Inputs["registry"])
		assert.Equal(t, "test-image", ctx.Inputs["image"])
		assert.Equal(t, "extra-value", ctx.Inputs["extra"])
		assert.Equal(t, "2024-01-06T12:00:00Z", ctx.Event.WorkflowRun.CreatedAt)
		assert.Equal(t, "2024-01-06T12:00:00Z", ctx.Event.HeadCommit.Timestamp)
	})

	// Test case 4: Invalid workflow inputs JSON
	t.Run("invalid workflow inputs json", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("GITHUB_WORKFLOW_INPUTS", "invalid json")

		_, err := LoadFromEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse workflow inputs")
	})
}

func TestLoadRunnerFromEnv(t *testing.T) {
	// Test case 1: Missing RUNNER_OS
	t.Run("missing runner os", func(t *testing.T) {
		os.Clearenv()
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
