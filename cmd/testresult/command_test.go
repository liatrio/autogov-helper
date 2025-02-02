package testresult_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gh-attest-util/cmd/testresult"

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

		cmd := testresult.NewCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)

		cmd.SetArgs([]string{
			"--results-path", resultsPath,
			"--subject-name", "test-subject",
			"--digest", "abc123",
		})

		err = cmd.Execute()
		require.NoError(t, err)

		var statement map[string]interface{}
		err = json.Unmarshal(output.Bytes(), &statement)
		require.NoError(t, err)

		// verify statement
		assert.Equal(t, "https://in-toto.io/Statement/v1", statement["_type"])
		assert.Equal(t, "https://in-toto.io/attestation/test-result/v0.1", statement["predicateType"])

		// verify subject
		subjects := statement["subject"].([]interface{})
		require.Len(t, subjects, 1)
		subject := subjects[0].(map[string]interface{})
		assert.Equal(t, "test-subject", subject["name"])
		digest := subject["digest"].(map[string]interface{})
		assert.Equal(t, "abc123", digest["sha256"])

		// verify predicate
		predicate := statement["predicate"].(map[string]interface{})
		assert.Equal(t, "WARNED", predicate["result"])

		config := predicate["configuration"].([]interface{})
		require.Len(t, config, 1)

		scanner := config[0].(map[string]interface{})
		assert.Equal(t, "grype", scanner["name"])
		assert.Equal(t, "https://github.com/anchore/grype/releases/tag/v0.87.0", scanner["downloadLocation"])

		scannerDigest := scanner["digest"].(map[string]interface{})
		assert.Equal(t, "0.87.0", scannerDigest["version"])
		assert.Equal(t, "5", scannerDigest["dbVersion"])
		assert.Equal(t, "2025-01-23T01:31:43Z", scannerDigest["dbBuilt"])

		assert.Equal(t, "https://toolbox-data.anchore.io/grype/databases/listing.json", predicate["url"])

		warnedTests := predicate["warnedTests"].([]interface{})
		require.Len(t, warnedTests, 1)
		assert.Equal(t, "vulnerability-CVE-2024-1234", warnedTests[0])
	})
}
