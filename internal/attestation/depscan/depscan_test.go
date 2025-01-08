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
			},
			{
				"vulnerability": {
					"id": "CVE-2023-5678",
					"severity": "MEDIUM",
					"cvss": [
						{
							"metrics": {
								"baseScore": 5.5
							}
						}
					]
				}
			}
		]
	}`

	err := os.WriteFile(resultsPath, []byte(sampleResults), 0600)
	require.NoError(t, err)

	t.Run("successfully parses grype results", func(t *testing.T) {
		scan, err := NewFromGrypeResults(Options{
			ResultsPath: resultsPath,
		})
		require.NoError(t, err)

		// Verify scanner info
		assert.Equal(t, "https://github.com/anchore/grype/releases/tag/v0.32.0", scan.Scanner.URI)
		assert.Equal(t, "0.32.0", scan.Scanner.Version)
		assert.Equal(t, "https://toolbox-data.anchore.io/grype/databases/listing.json", scan.Scanner.DB.URI)
		assert.Equal(t, "5", scan.Scanner.DB.Version)
		assert.Equal(t, "2024-01-06T14:00:00Z", scan.Scanner.DB.LastUpdate)

		// Verify metadata
		assert.Equal(t, "2024-01-06T14:00:00Z", scan.Metadata.ScanStartedOn)
		assert.Equal(t, "2024-01-06T15:00:00Z", scan.Metadata.ScanFinishedOn)

		// Verify vulnerabilities
		require.Len(t, scan.Scanner.Result, 2)

		// First vulnerability
		assert.Equal(t, "CVE-2023-1234", scan.Scanner.Result[0].ID)
		require.Len(t, scan.Scanner.Result[0].Severity, 2)
		assert.Equal(t, "nvd", scan.Scanner.Result[0].Severity[0].Method)
		assert.Equal(t, "HIGH", scan.Scanner.Result[0].Severity[0].Score)
		assert.Equal(t, "cvss_score", scan.Scanner.Result[0].Severity[1].Method)
		assert.Equal(t, "8.5", scan.Scanner.Result[0].Severity[1].Score)

		// Second vulnerability
		assert.Equal(t, "CVE-2023-5678", scan.Scanner.Result[1].ID)
		require.Len(t, scan.Scanner.Result[1].Severity, 2)
		assert.Equal(t, "nvd", scan.Scanner.Result[1].Severity[0].Method)
		assert.Equal(t, "MEDIUM", scan.Scanner.Result[1].Severity[0].Score)
		assert.Equal(t, "cvss_score", scan.Scanner.Result[1].Severity[1].Method)
		assert.Equal(t, "5.5", scan.Scanner.Result[1].Severity[1].Score)
	})

	t.Run("handles missing results file", func(t *testing.T) {
		_, err := NewFromGrypeResults(Options{
			ResultsPath: "nonexistent.json",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read results file")
	})

	t.Run("handles invalid json", func(t *testing.T) {
		invalidPath := filepath.Join(tmpDir, "invalid.json")
		err := os.WriteFile(invalidPath, []byte("invalid json"), 0600)
		require.NoError(t, err)

		_, err = NewFromGrypeResults(Options{
			ResultsPath: invalidPath,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse results")
	})

	t.Run("generates valid json output", func(t *testing.T) {
		scan, err := NewFromGrypeResults(Options{
			ResultsPath: resultsPath,
		})
		require.NoError(t, err)

		output, err := scan.Generate()
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(output, &result)
		assert.NoError(t, err)
		assert.Contains(t, result, "scanner")
		assert.Contains(t, result, "metadata")
	})

	t.Run("returns correct predicate type", func(t *testing.T) {
		scan := &DependencyScan{}
		assert.Equal(t, PredicateTypeURI, scan.Type())
	})
}
