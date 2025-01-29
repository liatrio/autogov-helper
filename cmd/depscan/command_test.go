package depscan_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gh-attest-util/cmd/depscan"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDepscanCommand(t *testing.T) {
	t.Run("generates valid dependency scan", func(t *testing.T) {
		tmpDir := t.TempDir()
		resultsPath := filepath.Join(tmpDir, "results.json")

		testData := []byte(`{
			"descriptor": {
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

		cmd := depscan.NewCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)

		cmd.SetArgs([]string{
			"--results-path", resultsPath,
			"--subject-name", "test-subject",
			"--digest", "sha256:abc123",
		})

		err = cmd.Execute()
		require.NoError(t, err)

		var predicate map[string]interface{}
		err = json.Unmarshal(output.Bytes(), &predicate)
		require.NoError(t, err)

		scanner := predicate["scanner"].(map[string]interface{})
		assert.Equal(t, "https://github.com/anchore/grype/releases/tag/v0.87.0", scanner["uri"])
		assert.Equal(t, "0.87.0", scanner["version"])

		db := scanner["db"].(map[string]interface{})
		assert.Equal(t, "https://toolbox-data.anchore.io/grype/databases/listing.json", db["uri"])
		assert.Equal(t, "5", db["version"])
		assert.Equal(t, "2025-01-23T01:31:43Z", db["lastUpdate"])

		results := scanner["result"].([]interface{})
		require.Len(t, results, 1)

		vuln := results[0].(map[string]interface{})
		assert.Equal(t, "CVE-2024-1234", vuln["id"])

		severities := vuln["severity"].([]interface{})
		require.Len(t, severities, 2)

		nvdSeverity := severities[0].(map[string]interface{})
		assert.Equal(t, "nvd", nvdSeverity["method"])
		assert.Equal(t, "Medium", nvdSeverity["score"])

		cvssScore := severities[1].(map[string]interface{})
		assert.Equal(t, "cvss_score", cvssScore["method"])
		assert.Equal(t, "7.5", cvssScore["score"])

		metadata := predicate["metadata"].(map[string]interface{})
		assert.Equal(t, "2025-01-23T01:31:43Z", metadata["scanStartedOn"])
		assert.Equal(t, "2025-01-24T00:18:00.27584939Z", metadata["scanFinishedOn"])
	})
}
