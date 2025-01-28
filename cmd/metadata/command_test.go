package metadata

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataCommand(t *testing.T) {
	// Set up environment variables
	os.Setenv("GITHUB_REPOSITORY", "test-repo")
	os.Setenv("GITHUB_REPOSITORY_OWNER", "test-owner")
	os.Setenv("GITHUB_SERVER_URL", "https://github.com")
	os.Setenv("GITHUB_SHA", "test-sha")
	os.Setenv("GITHUB_RUN_ID", "test-run-id")
	os.Setenv("GITHUB_RUN_NUMBER", "test-run-number")
	os.Setenv("GITHUB_WORKFLOW_REF", "test-workflow-ref")
	os.Setenv("GITHUB_JOB_STATUS", "test-job")
	os.Setenv("GITHUB_ACTOR", "test-actor")
	os.Setenv("RUNNER_OS", "test-os")
	os.Setenv("RUNNER_ARCH", "test-arch")
	os.Setenv("RUNNER_ENVIRONMENT", "test-runner")

	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Test container image type
	t.Run("container_image", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := NewCommand()
		cmd.SetOut(&buf)

		cmd.SetArgs([]string{
			"--subject-name", "test-subject",
			"--digest", "test-digest",
		})

		require.NoError(t, cmd.Execute())

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

		// Verify artifact data
		artifact := result["artifact"].(map[string]interface{})
		assert.Equal(t, "test-sha-test-run-number", artifact["version"])
		assert.Equal(t, "container-image", artifact["type"])
		assert.Equal(t, "test-digest", artifact["digest"])

		// Verify metadata
		metadata := result["metadata"].(map[string]interface{})
		repository := metadata["repository"].(map[string]interface{})
		assert.Equal(t, "test-repo", repository["name"])
		assert.Equal(t, "test-owner", repository["owner"])
		assert.Equal(t, "https://github.com", repository["url"])

		workflow := metadata["workflow"].(map[string]interface{})
		assert.Equal(t, "test-workflow-ref", workflow["ref"])
		assert.Equal(t, "test-run-id", workflow["id"])

		job := metadata["job"].(map[string]interface{})
		assert.Equal(t, "test-job", job["name"])
		assert.Equal(t, "test-run-id", job["id"])

		runner := metadata["runner"].(map[string]interface{})
		assert.Equal(t, "test-runner", runner["name"])
		assert.Equal(t, "test-os", runner["os"])

		commit := metadata["commit"].(map[string]interface{})
		assert.Equal(t, "test-sha", commit["sha"])
		assert.Equal(t, "test-actor", commit["author"])
		assert.Equal(t, "https://github.com/test-repo/commit/test-sha", commit["url"])
	})

	// Test blob type
	t.Run("blob", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := NewCommand()
		cmd.SetOut(&buf)

		cmd.SetArgs([]string{
			"--type", "blob",
			"--subject-path", tmpFile.Name(),
			"--digest", "test-digest",
		})

		require.NoError(t, cmd.Execute())

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

		// Verify artifact data
		artifact := result["artifact"].(map[string]interface{})
		assert.Equal(t, "test-sha-test-run-number", artifact["version"])
		assert.Equal(t, "blob", artifact["type"])
		assert.Equal(t, tmpFile.Name(), artifact["path"])
	})
}
