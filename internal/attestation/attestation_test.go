package attestation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"autogov-helper/internal/types"
	"autogov-helper/internal/util/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestOptions() types.Options {
	now := time.Now().UTC()
	return types.Options{
		Type:            types.ArtifactTypeContainerImage,
		Registry:        "ghcr.io",
		Repository:      "test-org/test-repo",
		FullName:        "ghcr.io/test-org/test-repo@sha256:test",
		Digest:          "sha256:test",
		Version:         "test-sha-test-run-number",
		Created:         now,
		GitHubServerURL: "https://github.com",
		Owner:           "test-org",
		OwnerID:         "test-owner-id",
		OS:              "test-os",
		Arch:            "test-arch",
		Environment:     "test-env",
		WorkflowRefPath: "test-workflow-ref",
		Branch:          "main",
		Event:           "push",
		RunNumber:       "1",
		RunID:           "123",
		Status:          "success",
		TriggeredBy:     "test-user",
		StartedAt:       now,
		CompletedAt:     now,
		SHA:             "test-sha",
		Timestamp:       now,
		OrgName:         "test-org",
		PolicyRef:       "https://github.com/test-org/test-policy",
		ControlIds:      []string{"test-control"},
		Permissions: map[string]string{
			"id-token":     "write",
			"attestations": "write",
			"contents":     "read",
			"packages":     "write",
		},
		Inputs: map[string]any{
			"test-input": "test-value",
		},
	}
}

func TestGenerateMetadata(t *testing.T) {
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	t.Run("valid_container_image_metadata", func(t *testing.T) {
		// create temp dir
		tmpDir, err := os.MkdirTemp("", "test-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		// create output file
		outputPath := filepath.Join(tmpDir, "metadata.json")

		// create test options
		opts := createTestOptions()
		opts.Type = types.ArtifactTypeContainerImage
		opts.Registry = "ghcr.io"
		// Don't override fullName since it's already set correctly in createTestOptions
		opts.Digest = "sha256:test"
		opts.SHA = "test-sha"
		opts.RunNumber = "test-run-number"
		opts.PolicyRef = "https://github.com/test-org/test-policy"
		opts.ControlIds = []string{"test-control"}

		// generate metadata
		err = GenerateMetadata(opts, outputPath)
		require.NoError(t, err)

		// verify output file exists
		_, err = os.Stat(outputPath)
		require.NoError(t, err)

		// read output file
		data, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		// parse output
		var predicate map[string]interface{}
		err = json.Unmarshal(data, &predicate)
		require.NoError(t, err)

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
		assert.Equal(t, "", repoData["repositoryId"])
		assert.Equal(t, "https://github.com", repoData["githubServerURL"])

		ownerData := predicate["ownerData"].(map[string]interface{})
		assert.Equal(t, "test-org", ownerData["owner"])
		assert.Equal(t, "test-owner-id", ownerData["ownerId"])

		runnerData := predicate["runnerData"].(map[string]interface{})
		assert.Equal(t, "test-os", runnerData["os"])
		assert.Equal(t, "test-arch", runnerData["arch"])
		assert.Equal(t, "test-env", runnerData["environment"])

		workflowData := predicate["workflowData"].(map[string]interface{})
		assert.Equal(t, "test-workflow-ref", workflowData["workflowRefPath"])
		assert.Equal(t, "main", workflowData["branch"])
		assert.Equal(t, "push", workflowData["event"])
		assert.Equal(t, "test-value", workflowData["inputs"].(map[string]interface{})["test-input"])

		jobData := predicate["jobData"].(map[string]interface{})
		assert.Equal(t, "test-run-number", jobData["runNumber"])
		assert.Equal(t, "123", jobData["runId"])
		assert.Equal(t, "success", jobData["status"])
		assert.Equal(t, "test-user", jobData["triggeredBy"])

		organization := predicate["organization"].(map[string]interface{})
		assert.Equal(t, "test-org", organization["name"])

		compliance := predicate["compliance"].(map[string]interface{})
		assert.Equal(t, "https://github.com/test-org/test-policy", compliance["policyRef"])
		assert.Equal(t, []interface{}{"test-control"}, compliance["controlIds"])

		security := predicate["security"].(map[string]interface{})
		permissions := security["permissions"].(map[string]interface{})
		assert.Equal(t, "write", permissions["id-token"])
		assert.Equal(t, "write", permissions["attestations"])
		assert.Equal(t, "read", permissions["contents"])
		assert.Equal(t, "write", permissions["packages"])
	})
}

func TestGenerateDepscan(t *testing.T) {
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "depscan.json")
	resultsPath := filepath.Join(tmpDir, "results.json")

	// create test grype results
	testData := []byte(`{
		"descriptor": {
			"name": "grype",
			"version": "0.87.0",
			"timestamp": "2025-01-24T00:18:00.27584939Z",
			"configuration": {
				"db": {
					"update-url": "https://toolbox-data.anchore.io/grype/databases/listing.json"
				}
			},
			"db": {
				"built": "2025-01-23T01:31:43Z",
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

	opts := DepscanOptions{
		Type:        types.ArtifactTypeContainerImage,
		SubjectName: "test-image",
		Digest:      "sha256:test",
		ResultsPath: resultsPath,
	}

	err = GenerateDepscan(opts, outputPath)
	require.NoError(t, err)

	// verify output file exists and contains valid JSON
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	assert.NoError(t, err)
}

func TestGenerateMetadataAttestation(t *testing.T) {
	// Set up test environment
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// Create test options
	opts := createTestOptions()

	// Generate metadata
	err := GenerateMetadata(opts, "")
	require.NoError(t, err)
}
