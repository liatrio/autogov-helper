package template

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderMetadataTemplate(t *testing.T) {
	testCases := []struct {
		name     string
		data     MetadataTemplateData
		validate func(t *testing.T, output []byte)
	}{
		{
			name: "container image with remote registry",
			data: MetadataTemplateData{
				Type:            "container-image",
				Version:         "1.0.0",
				Digest:          "sha256:abc123",
				Created:         "2024-01-27T19:48:49Z",
				Registry:        "ghcr.io",
				Repository:      "owner/repo",
				FullName:        "ghcr.io/owner/repo@sha256:abc123",
				RepositoryID:    "123",
				GitHubServerURL: "https://github.com",
				Owner:           "owner",
				OwnerID:         "456",
				RunnerOS:        "linux",
				RunnerArch:      "X64",
				WorkflowInputs:  "{}",
			},
			validate: func(t *testing.T, output []byte) {
				var data map[string]interface{}
				err := json.Unmarshal(output, &data)
				require.NoError(t, err)

				artifact := data["artifact"].(map[string]interface{})
				assert.Equal(t, "container-image", artifact["type"])
				assert.Equal(t, "ghcr.io", artifact["registry"])
				assert.Equal(t, "ghcr.io/owner/repo@sha256:abc123", artifact["fullName"])
				assert.Equal(t, "write", data["security"].(map[string]interface{})["permissions"].(map[string]interface{})["packages"])
			},
		},
		{
			name: "blob",
			data: MetadataTemplateData{
				Type:            "blob",
				Version:         "1.0.0",
				Created:         "2024-01-27T19:48:49Z",
				Path:            "path/to/blob",
				Repository:      "owner/repo",
				RepositoryID:    "123",
				GitHubServerURL: "https://github.com",
				Owner:           "owner",
				OwnerID:         "456",
				RunnerOS:        "linux",
				RunnerArch:      "X64",
				WorkflowInputs:  "{}",
			},
			validate: func(t *testing.T, output []byte) {
				var data map[string]interface{}
				err := json.Unmarshal(output, &data)
				require.NoError(t, err)

				artifact := data["artifact"].(map[string]interface{})
				assert.Equal(t, "blob", artifact["type"])
				assert.Equal(t, "path/to/blob", artifact["path"])
				assert.Equal(t, "none", data["security"].(map[string]interface{})["permissions"].(map[string]interface{})["packages"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := RenderTemplate("metadata", tc.data)
			require.NoError(t, err)
			tc.validate(t, output)
		})
	}
}

func TestRenderDepscanTemplate(t *testing.T) {
	data := DepscanTemplateData{
		ScannerURI:     "https://github.com/anchore/grype/releases/tag/v0.87.0",
		ScannerVersion: "0.87.0",
		DBVersion:      "5",
		DBLastUpdate:   "2025-01-23T01:31:43Z",
		Created:        "2025-01-24T00:18:00.27584939Z",
		Results: `[
			{
				"id": "CVE-2024-1234",
				"severity": [
					{
						"method": "nvd",
						"score": "Medium"
					},
					{
						"method": "cvss_score",
						"score": "7.5"
					}
				]
			}
		]`,
	}

	output, err := RenderTemplate("depscan", data)
	require.NoError(t, err)

	var rendered map[string]interface{}
	err = json.Unmarshal(output, &rendered)
	require.NoError(t, err)

	scanner := rendered["scanner"].(map[string]interface{})
	assert.Equal(t, "https://github.com/anchore/grype/releases/tag/v0.87.0", scanner["uri"])
	assert.Equal(t, "0.87.0", scanner["version"])

	db := scanner["db"].(map[string]interface{})
	assert.Equal(t, "https://toolbox-data.anchore.io/grype/databases/listing.json", db["uri"])
	assert.Equal(t, "5", db["version"])
	assert.Equal(t, "2025-01-23T01:31:43Z", db["lastUpdate"])

	results := scanner["result"].([]interface{})
	require.Len(t, results, 1)

	result := results[0].(map[string]interface{})
	assert.Equal(t, "CVE-2024-1234", result["id"])

	severities := result["severity"].([]interface{})
	require.Len(t, severities, 2)

	nvdSeverity := severities[0].(map[string]interface{})
	assert.Equal(t, "nvd", nvdSeverity["method"])
	assert.Equal(t, "Medium", nvdSeverity["score"])

	cvssScore := severities[1].(map[string]interface{})
	assert.Equal(t, "cvss_score", cvssScore["method"])
	assert.Equal(t, "7.5", cvssScore["score"])

	metadata := rendered["metadata"].(map[string]interface{})
	assert.Equal(t, "2025-01-23T01:31:43Z", metadata["scanStartedOn"])
	assert.Equal(t, "2025-01-24T00:18:00.27584939Z", metadata["scanFinishedOn"])
}
