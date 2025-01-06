package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataCommand(t *testing.T) {
	// Setup test environment
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
		// Create a buffer to capture output
		var buf bytes.Buffer

		// Create and configure command
		cmd := newMetadataCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		// Set command arguments
		cmd.SetArgs([]string{
			"--subject-name", "test-image",
			"--digest", "sha256:123",
			"--registry", "ghcr.io",
			"--policy-ref", "https://example.com/policy",
			"--control-ids", "TEST-001,TEST-002",
		})

		// Execute command
		err := cmd.Execute()
		assert.NoError(t, err)

		// Get output
		output := buf.String()
		assert.NotEmpty(t, output)

		// Verify output is valid JSON
		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		assert.NoError(t, err)

		// Verify required sections exist
		assert.Contains(t, result, "artifact")
		assert.Contains(t, result, "repositoryData")
		assert.Contains(t, result, "security")

		// Verify specific values
		artifact := result["artifact"].(map[string]interface{})
		assert.Equal(t, "abc1234-1", artifact["version"])
		assert.Equal(t, "sha256:123", artifact["digest"])
		assert.Equal(t, "container-image", artifact["type"])
		assert.Equal(t, "ghcr.io", artifact["registry"])
		assert.Equal(t, "test-image", artifact["fullName"])
	})

	t.Run("requires mandatory flags", func(t *testing.T) {
		cmd := newMetadataCmd()
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required flag")
	})
}

func TestDepscanCommand(t *testing.T) {
	// Create temporary test file
	tmpDir := t.TempDir()
	resultsPath := filepath.Join(tmpDir, "results.json")

	sampleResults := `{
		"descriptor": {
			"version": "0.32.0",
			"configuration": {
				"db": {
					"update-url": "https://toolbox-data.anchore.io/grype/databases/listing.json"
				}
			},
			"db": {
				"schemaVersion": "5",
				"built": "2024-01-06T14:00:00Z"
			},
			"timestamp": "2024-01-06T15:00:00Z"
		},
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2023-1234",
					"severity": "HIGH",
					"cvss": [
						{
							"metrics": {
								"baseScore": 8.5
							}
						}
					]
				}
			}
		]
	}`

	err := os.WriteFile(resultsPath, []byte(sampleResults), 0644)
	require.NoError(t, err)

	t.Run("generates valid dependency scan", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := newDepscanCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		cmd.SetArgs([]string{
			"--results-path", resultsPath,
		})

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.NotEmpty(t, output)

		var result map[string]interface{}
		err = json.Unmarshal([]byte(output), &result)
		assert.NoError(t, err)

		assert.Contains(t, result, "scanner")
		assert.Contains(t, result, "metadata")

		scanner := result["scanner"].(map[string]interface{})
		assert.Equal(t, "0.32.0", scanner["version"])
		assert.Contains(t, scanner, "result")
	})

	t.Run("requires results-path flag", func(t *testing.T) {
		cmd := newDepscanCmd()
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required flag")
	})
}
