package depscan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDepscanCommand(t *testing.T) {
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

	err := os.WriteFile(resultsPath, []byte(sampleResults), 0600)
	require.NoError(t, err)

	t.Run("generates valid dependency scan", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := NewCommand()
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
		cmd := NewCommand()
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required flag")
	})
}
