package metadata

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMetadataCommand(t *testing.T) {
	testEnv := map[string]string{
		"GITHUB_REPOSITORY":          "test-org/test-repo",
		"GITHUB_REPOSITORY_ID":       "12345",
		"GITHUB_SERVER_URL":          "https://github.com",
		"GITHUB_REPOSITORY_OWNER":    "test-org",
		"GITHUB_REPOSITORY_OWNER_ID": "67890",
		"RUNNER_OS":                  "Linux",
		"RUNNER_ARCH":                "X64",
		"RUNNER_ENVIRONMENT":         "github-hosted",
		"GITHUB_WORKFLOW_REF":        "test-org/test-repo/.github/workflows/test.yml@main",
		"GITHUB_REF_NAME":            "main",
		"GITHUB_EVENT_NAME":          "push",
		"GITHUB_RUN_NUMBER":          "123",
		"GITHUB_RUN_ID":              "456",
		"GITHUB_JOB_STATUS":          "success",
		"GITHUB_ACTOR":               "test-user",
		"GITHUB_SHA":                 "abcdef123456789",
		"GITHUB_WORKFLOW_INPUTS":     "{}",
	}

	originalEnv := map[string]string{}
	for k := range testEnv {
		originalEnv[k] = os.Getenv(k)
	}

	for k, v := range testEnv {
		os.Setenv(k, v)
	}

	defer func() {
		for k, v := range originalEnv {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	now := time.Now().UTC()
	os.Setenv("GITHUB_JOB_STARTED_AT", now.Format(time.RFC3339))
	os.Setenv("GITHUB_JOB_COMPLETED_AT", now.Add(time.Minute).Format(time.RFC3339))
	os.Setenv("GITHUB_EVENT_TIMESTAMP", now.Format(time.RFC3339))

	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "container image",
			args: []string{
				"--type", "image",
				"--subject-name", "ghcr.io/test-org/test-repo",
				"--subject-digest", "sha256:test",
				"--output", filepath.Join(tmpDir, "metadata.json"),
			},
		},
		{
			name: "blob",
			args: []string{
				"--type", "blob",
				"--subject-path", "test-file.txt",
				"--output", filepath.Join(tmpDir, "blob-metadata.json"),
			},
		},
		{
			name: "container image without digest",
			args: []string{
				"--type", "image",
				"--subject-name", "ghcr.io/test-org/test-repo",
			},
			wantErr: true,
		},
		{
			name: "container image without subject name",
			args: []string{
				"--type", "image",
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
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			var output []byte
			for i, arg := range tt.args {
				if arg == "--output" {
					output, err = os.ReadFile(tt.args[i+1])
					assert.NoError(t, err)
					break
				}
			}

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			assert.NoError(t, err)

			// verify artifact exists
			artifact, ok := result["artifact"].(map[string]interface{})
			assert.True(t, ok, "artifact field should be a map")
			assert.NotEmpty(t, artifact["version"])
			assert.NotEmpty(t, artifact["created"])

			// verify type-specific fields
			if tt.name == "container image" {
				assert.Equal(t, "container-image", artifact["type"])
				assert.Equal(t, fmt.Sprintf("ghcr.io/test-org/test-repo@sha256:test"), artifact["fullName"])
				assert.Equal(t, "sha256:test", artifact["digest"])
			} else {
				assert.Equal(t, "blob", artifact["type"])
				assert.Equal(t, "test-file.txt", artifact["path"])
			}

			// verify other reqs exist
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
}
