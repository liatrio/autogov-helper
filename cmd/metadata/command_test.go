package metadata

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataCommand(t *testing.T) {
	os.Setenv("GITHUB_REPOSITORY", "test-repo")
	os.Setenv("GITHUB_REPOSITORY_OWNER", "test-owner")
	os.Setenv("GITHUB_REPOSITORY_ID", "123")
	os.Setenv("GITHUB_SERVER_URL", "https://github.com")
	os.Setenv("GITHUB_REPOSITORY_OWNER_ID", "456")
	os.Setenv("GITHUB_WORKFLOW_REF", "main")
	os.Setenv("GITHUB_REF_NAME", "main")
	os.Setenv("GITHUB_EVENT_NAME", "push")
	os.Setenv("GITHUB_SHA", "abc1234")
	os.Setenv("GITHUB_RUN_NUMBER", "1")
	os.Setenv("GITHUB_RUN_ID", "789")
	os.Setenv("GITHUB_ACTOR", "test-user")
	os.Setenv("GITHUB_JOB_STATUS", "success")
	os.Setenv("INPUT_TEST", "value")

	os.Setenv("RUNNER_OS", "Linux")
	os.Setenv("RUNNER_ARCH", "X64")
	os.Setenv("RUNNER_ENVIRONMENT", "github-hosted")

	t.Run("generates valid metadata", func(t *testing.T) {
		var buf bytes.Buffer

		cmd := NewCommand()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		cmd.SetArgs([]string{
			"--subject-name", "test-image",
			"--digest", "sha256:123",
			"--registry", "ghcr.io",
			"--policy-ref", "https://example.com/policy",
			"--control-ids", "TEST-001,TEST-002",
		})

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.NotEmpty(t, output)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		assert.NoError(t, err)

		assert.Contains(t, result, "artifact")
		assert.Contains(t, result, "repositoryData")
		assert.Contains(t, result, "security")

		artifact := result["artifact"].(map[string]interface{})
		assert.Equal(t, "abc1234-1", artifact["version"])
		assert.Equal(t, "sha256:123", artifact["digest"])
		assert.Equal(t, "container-image", artifact["type"])
		assert.Equal(t, "ghcr.io", artifact["registry"])
		assert.Equal(t, "test-image", artifact["fullName"])
	})

	// ... rest of metadata tests
}
