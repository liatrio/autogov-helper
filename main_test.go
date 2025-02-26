package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"autogov-helper/internal/util/testutil"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainCommand(t *testing.T) {
	t.Run("shows help", func(t *testing.T) {
		cmd := &cobra.Command{
			Use:   "autogov-helper",
			Short: "GitHub Actions attestation utilities",
			Long:  "GitHub Actions attestation utilities for generating attestations",
		}

		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetArgs([]string{"--help"})

		err := cmd.Execute()
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "GitHub Actions attestation utilities")
	})
}

func TestMetadataCommand(t *testing.T) {
	// set up test env
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// create temp dir
	tmpDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// create output file
	outputPath := filepath.Join(tmpDir, "metadata.json")

	// set up test env vars
	os.Setenv("GITHUB_REPOSITORY", "test-org/test-repo")
	os.Setenv("GITHUB_REPOSITORY_ID", "123")
	os.Setenv("GITHUB_REPOSITORY_OWNER", "test-org")
	os.Setenv("GITHUB_REPOSITORY_OWNER_ID", "456")
	os.Setenv("GITHUB_SERVER_URL", "https://github.com")
	os.Setenv("GITHUB_SHA", "abc123")
	os.Setenv("GITHUB_REF_NAME", "main")
	os.Setenv("GITHUB_EVENT_NAME", "push")
	os.Setenv("GITHUB_ACTOR", "test-user")
	os.Setenv("GITHUB_RUN_ID", "789")
	os.Setenv("GITHUB_RUN_NUMBER", "1")
	os.Setenv("GITHUB_WORKFLOW_REF", "test-workflow")
	os.Setenv("RUNNER_OS", "Linux")
	os.Setenv("RUNNER_ARCH", "X64")
	os.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	os.Setenv("GITHUB_WORKFLOW_INPUTS", `{"test-input":"test-value"}`)

	// run command
	cmd := newRootCommand()
	cmd.SetArgs([]string{
		"metadata",
		"--type", "image",
		"--subject-name", "ghcr.io/test-org/test-repo",
		"--subject-digest", "sha256:test",
		"--output", outputPath,
	})

	err = cmd.Execute()
	require.NoError(t, err)

	// verify output file exists and contains valid JSON
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var predicate map[string]interface{}
	err = json.Unmarshal(data, &predicate)
	assert.NoError(t, err)

	// verify predicate fields
	assert.NotNil(t, predicate["artifact"])
	assert.NotNil(t, predicate["repositoryData"])
	assert.NotNil(t, predicate["ownerData"])
	assert.NotNil(t, predicate["runnerData"])
	assert.NotNil(t, predicate["workflowData"])
	assert.NotNil(t, predicate["jobData"])
	assert.NotNil(t, predicate["commitData"])
	assert.NotNil(t, predicate["organization"])
	assert.NotNil(t, predicate["compliance"])
	assert.NotNil(t, predicate["security"])

	// verify specific fields
	artifact := predicate["artifact"].(map[string]interface{})
	assert.Equal(t, "container-image", artifact["type"])
	assert.Equal(t, "ghcr.io/test-org/test-repo@sha256:test", artifact["fullName"])
	assert.Equal(t, "sha256:test", artifact["digest"])
	assert.Equal(t, "ghcr.io", artifact["registry"])

	repoData := predicate["repositoryData"].(map[string]interface{})
	assert.Equal(t, "test-org/test-repo", repoData["repository"])
	assert.Equal(t, "123", repoData["repositoryId"])
	assert.Equal(t, "https://github.com", repoData["githubServerURL"])

	ownerData := predicate["ownerData"].(map[string]interface{})
	assert.Equal(t, "test-org", ownerData["owner"])
	assert.Equal(t, "456", ownerData["ownerId"])

	runnerData := predicate["runnerData"].(map[string]interface{})
	assert.Equal(t, "Linux", runnerData["os"])
	assert.Equal(t, "X64", runnerData["arch"])
	assert.Equal(t, "github-hosted", runnerData["environment"])

	workflowData := predicate["workflowData"].(map[string]interface{})
	assert.Equal(t, "test-workflow", workflowData["workflowRefPath"])
	assert.Equal(t, "main", workflowData["branch"])
	assert.Equal(t, "push", workflowData["event"])
	assert.Equal(t, "test-value", workflowData["inputs"].(map[string]interface{})["test-input"])

	jobData := predicate["jobData"].(map[string]interface{})
	assert.Equal(t, "1", jobData["runNumber"])
	assert.Equal(t, "789", jobData["runId"])
	assert.Equal(t, "success", jobData["status"])
	assert.Equal(t, "test-user", jobData["triggeredBy"])

	organization := predicate["organization"].(map[string]interface{})
	assert.Equal(t, "test-org", organization["name"])

	compliance := predicate["compliance"].(map[string]interface{})
	assert.Equal(t, "https://github.com/liatrio/demo-gh-autogov-policy-library", compliance["policyRef"])
	assert.Contains(t, compliance["controlIds"], "test-org-PROVENANCE-001")
	assert.Contains(t, compliance["controlIds"], "test-org-SBOM-002")
	assert.Contains(t, compliance["controlIds"], "test-org-METADATA-003")

	security := predicate["security"].(map[string]interface{})
	permissions := security["permissions"].(map[string]interface{})
	assert.Equal(t, "write", permissions["id-token"])
	assert.Equal(t, "write", permissions["attestations"])
	assert.Equal(t, "read", permissions["contents"])
	assert.Equal(t, "write", permissions["packages"])
}

func TestDepscanCommand(t *testing.T) {
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// create temp dir
	tmpDir := t.TempDir()

	// create test results file
	resultsPath := filepath.Join(tmpDir, "results.json")
	testData := []byte(`{
		"descriptor": {
			"name": "grype",
			"version": "0.74.7",
			"timestamp": "2024-01-27T19:48:49Z",
			"configuration": {
				"db": {
					"update-url": "https://toolbox-data.anchore.io/grype/databases/listing.json"
				}
			},
			"db": {
				"built": "2024-01-27T19:48:49Z",
				"schemaVersion": "5"
			}
		},
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2024-1234",
					"severity": "Medium",
					"cvss": [
						{
							"metrics": {
								"baseScore": 7.5
							}
						}
					]
				}
			}
		]
	}`)

	err := os.WriteFile(resultsPath, testData, 0600)
	require.NoError(t, err)

	// create output file
	outputPath := filepath.Join(tmpDir, "depscan.json")

	// run command
	cmd := newRootCommand()
	cmd.SetArgs([]string{
		"depscan",
		"--type", "image",
		"--subject-name", "test-image",
		"--digest", "sha256:test",
		"--results-path", resultsPath,
		"--output", outputPath,
	})

	err = cmd.Execute()
	require.NoError(t, err)

	// verify output file exists and contains valid JSON
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	assert.NoError(t, err)

	// verify scanner fields
	scanner := result["scanner"].(map[string]interface{})
	assert.Equal(t, "grype", scanner["name"])
	assert.Equal(t, "0.74.7", scanner["version"])
	assert.Equal(t, "https://github.com/anchore/grype/releases/tag/v0.74.7", scanner["uri"])

	db := scanner["db"].(map[string]interface{})
	assert.Equal(t, "https://toolbox-data.anchore.io/grype/databases/listing.json", db["uri"])
	assert.Equal(t, "5", db["version"])
	assert.Equal(t, "2024-01-27T19:48:49Z", db["lastUpdate"])

	results := scanner["result"].([]interface{})
	assert.Len(t, results, 1)

	result1 := results[0].(map[string]interface{})
	assert.Equal(t, "CVE-2024-1234", result1["id"])

	severities := result1["severity"].([]interface{})
	assert.Len(t, severities, 2)

	severity1 := severities[0].(map[string]interface{})
	assert.Equal(t, "nvd", severity1["method"])
	assert.Equal(t, "Medium", severity1["score"])

	severity2 := severities[1].(map[string]interface{})
	assert.Equal(t, "cvss_score", severity2["method"])
	assert.Equal(t, "7.5", severity2["score"])
}
