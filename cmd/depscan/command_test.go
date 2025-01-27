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
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"version": 1,
			"metadata": {
				"timestamp": "2024-03-14T12:00:00Z",
				"tools": [
					{
						"vendor": "anchore",
						"name": "grype",
						"version": "0.74.7"
					}
				]
			},
			"vulnerabilities": [
				{
					"id": "CVE-2024-1234",
					"source": {
						"name": "nvd",
						"url": "https://nvd.nist.gov"
					},
					"ratings": [
						{
							"source": {
								"name": "nvd"
							},
							"score": 7.5,
							"severity": "HIGH",
							"method": "CVSSv3"
						}
					]
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

		var result map[string]interface{}
		err = json.Unmarshal(output.Bytes(), &result)
		require.NoError(t, err)

		predicate := result["predicate"].(map[string]interface{})
		scanner := predicate["scanner"].(map[string]interface{})

		assert.Equal(t, "https://github.com/anchore/grype/releases/tag/v0.74.7", scanner["uri"])
		assert.Equal(t, "0.74.7", scanner["version"])

		db := scanner["db"].(map[string]interface{})
		assert.Equal(t, "grype", db["name"])
		assert.Equal(t, "1.5", db["version"])
		assert.Equal(t, "2024-03-14T12:00:00Z", db["lastUpdated"])

		results := scanner["result"].([]interface{})
		require.Len(t, results, 1)

		vuln := results[0].(map[string]interface{})
		assert.Equal(t, "CVE-2024-1234", vuln["id"])

		severity := vuln["severity"].(map[string]interface{})
		assert.Equal(t, "CVSSv3", severity["method"])
		assert.Equal(t, "7.5", severity["score"])
	})
}
