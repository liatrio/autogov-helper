package metadata

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMetadataCommand(t *testing.T) {
	// Set up test environment variables
	os.Setenv("GITHUB_REPOSITORY", "test-org/test-repo")
	os.Setenv("GITHUB_REPOSITORY_ID", "12345")
	os.Setenv("GITHUB_SERVER_URL", "https://github.com")
	os.Setenv("GITHUB_REPOSITORY_OWNER", "test-org")
	os.Setenv("GITHUB_REPOSITORY_OWNER_ID", "67890")
	os.Setenv("RUNNER_OS", "Linux")
	os.Setenv("RUNNER_ARCH", "X64")
	os.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	os.Setenv("GITHUB_WORKFLOW_REF", "test-org/test-repo/.github/workflows/test.yml@main")
	os.Setenv("GITHUB_REF_NAME", "main")
	os.Setenv("GITHUB_EVENT_NAME", "push")
	os.Setenv("GITHUB_RUN_NUMBER", "123")
	os.Setenv("GITHUB_RUN_ID", "456")
	os.Setenv("GITHUB_JOB_STATUS", "success")
	os.Setenv("GITHUB_ACTOR", "test-user")
	os.Setenv("GITHUB_SHA", "abcdef123456")
	os.Setenv("GITHUB_ORGANIZATION", "test-org")
	os.Setenv("POLICY_REF", "test-policy")
	os.Setenv("CONTROL_IDS", "test-control")

	now := time.Now().UTC()
	os.Setenv("GITHUB_JOB_STARTED_AT", now.Format(time.RFC3339))
	os.Setenv("GITHUB_JOB_COMPLETED_AT", now.Add(time.Minute).Format(time.RFC3339))
	os.Setenv("GITHUB_EVENT_TIMESTAMP", now.Format(time.RFC3339))

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "container image",
			args: []string{
				"--type", "container-image",
				"--subject-name", "ghcr.io/test-org/test-repo",
				"--subject-digest", "sha256:test",
			},
		},
		{
			name: "blob",
			args: []string{
				"--type", "blob",
				"--subject-path", "test-file.txt",
			},
		},
		{
			name: "container image without digest",
			args: []string{
				"--type", "container-image",
				"--subject-name", "ghcr.io/test-org/test-repo",
			},
			wantErr: true,
		},
		{
			name: "container image without subject name",
			args: []string{
				"--type", "container-image",
				"--subject-digest", "sha256:test",
			},
			wantErr: true,
		},
		{
			name: "blob without subject path",
			args: []string{
				"--type", "blob",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCommand()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Verify output is valid JSON
			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			assert.NoError(t, err)

			// Verify artifact data exists
			artifact, ok := result["artifact"].(map[string]interface{})
			assert.True(t, ok, "artifact field should be a map")
			assert.NotEmpty(t, artifact["version"])
			assert.NotEmpty(t, artifact["created"])

			// Verify type-specific fields
			if tt.name == "container image" {
				assert.Equal(t, "container-image", artifact["type"])
				assert.Equal(t, "ghcr.io/test-org/test-repo", artifact["fullName"])
				assert.Equal(t, "sha256:test", artifact["digest"])
			} else {
				assert.Equal(t, "blob", artifact["type"])
				assert.Equal(t, "test-file.txt", artifact["path"])
			}

			// Verify other required sections exist
			assert.Contains(t, result, "repositoryData")
			assert.Contains(t, result, "ownerData")
			assert.Contains(t, result, "runnerData")
			assert.Contains(t, result, "workflowData")
			assert.Contains(t, result, "jobData")
			assert.Contains(t, result, "commitData")
			assert.Contains(t, result, "organization")
			assert.Contains(t, result, "compliance")
			assert.Contains(t, result, "security")
		})
	}

	// Clean up environment variables
	os.Clearenv()
}
