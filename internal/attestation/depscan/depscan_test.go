package depscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFromGrypeResults(t *testing.T) {
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

	os.Setenv("GITHUB_TOKEN", os.Getenv("GH_TOKEN"))

	opts := Options{
		ResultsPath: resultsPath,
		SubjectName: "test-subject",
		Digest:      "test-digest",
	}

	scan, err := NewFromGrypeResults(opts)
	require.NoError(t, err)

	assert.Equal(t, "https://github.com/anchore/grype/releases/tag/v0.74.7", scan.Scanner.URI)
	assert.Equal(t, "0.74.7", scan.Scanner.Version)

	assert.Equal(t, "grype", scan.Scanner.Db.Name)
	assert.Equal(t, "1.5", scan.Scanner.Db.Version)
	assert.Equal(t, "2024-03-14T12:00:00Z", scan.Scanner.Db.LastUpdated)

	require.Len(t, scan.Scanner.Result, 1)
	result := scan.Scanner.Result[0]
	assert.Equal(t, "CVE-2024-1234", result.ID)
	assert.Equal(t, "CVSSv3", result.Severity.Method)
	assert.Equal(t, "7.5", result.Severity.Score)

	data, err := scan.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(data, &jsonMap)
	require.NoError(t, err)
}
