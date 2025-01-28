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
	testCases := []struct {
		name         string
		testData     string
		expectedScan *DependencyScan
	}{
		{
			name: "valid scan results",
			testData: `{
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
			}`,
			expectedScan: &DependencyScan{
				Scanner: struct {
					URI     string `json:"uri"`
					Version string `json:"version"`
					DB      struct {
						URI        string `json:"uri"`
						Version    string `json:"version"`
						LastUpdate string `json:"lastUpdate"`
					} `json:"db"`
					Result []struct {
						ID       string `json:"id"`
						Severity []struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					} `json:"result"`
				}{
					URI:     "https://github.com/anchore/grype/releases/tag/v0.87.0",
					Version: "0.87.0",
					DB: struct {
						URI        string `json:"uri"`
						Version    string `json:"version"`
						LastUpdate string `json:"lastUpdate"`
					}{
						URI:        "https://toolbox-data.anchore.io/grype/databases/listing.json",
						Version:    "5",
						LastUpdate: "2025-01-23T01:31:43Z",
					},
					Result: []struct {
						ID       string `json:"id"`
						Severity []struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					}{
						{
							ID: "CVE-2024-1234",
							Severity: []struct {
								Method string `json:"method"`
								Score  string `json:"score"`
							}{
								{
									Method: "nvd",
									Score:  "Medium",
								},
								{
									Method: "cvss_score",
									Score:  "7.5",
								},
							},
						},
					},
				},
				Metadata: struct {
					ScanStartedOn  string `json:"scanStartedOn"`
					ScanFinishedOn string `json:"scanFinishedOn"`
				}{
					ScanStartedOn:  "2025-01-23T01:31:43Z",
					ScanFinishedOn: "2025-01-24T00:18:00.27584939Z",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// create temp file w/ test data
			tmpDir := t.TempDir()
			resultsPath := filepath.Join(tmpDir, "results.json")
			err := os.WriteFile(resultsPath, []byte(tc.testData), 0600)
			require.NoError(t, err)

			opts := Options{
				ResultsPath: resultsPath,
				SubjectName: "test-subject",
				Digest:      "test-digest",
			}

			scan, err := NewFromGrypeResults(opts)
			assert.NoError(t, err)
			assert.NotNil(t, scan)

			// verify scanner fields
			assert.Equal(t, tc.expectedScan.Scanner.URI, scan.Scanner.URI)
			assert.Equal(t, tc.expectedScan.Scanner.Version, scan.Scanner.Version)

			// verify DB fields
			assert.Equal(t, tc.expectedScan.Scanner.DB.URI, scan.Scanner.DB.URI)
			assert.Equal(t, tc.expectedScan.Scanner.DB.Version, scan.Scanner.DB.Version)
			assert.Equal(t, tc.expectedScan.Scanner.DB.LastUpdate, scan.Scanner.DB.LastUpdate)

			// verify metadata
			assert.Equal(t, tc.expectedScan.Metadata.ScanStartedOn, scan.Metadata.ScanStartedOn)
			assert.Equal(t, tc.expectedScan.Metadata.ScanFinishedOn, scan.Metadata.ScanFinishedOn)

			// verify results
			require.Equal(t, len(tc.expectedScan.Scanner.Result), len(scan.Scanner.Result))
			for i, expectedResult := range tc.expectedScan.Scanner.Result {
				assert.Equal(t, expectedResult.ID, scan.Scanner.Result[i].ID)
				require.Equal(t, len(expectedResult.Severity), len(scan.Scanner.Result[i].Severity))

				for j, expectedSeverity := range expectedResult.Severity {
					assert.Equal(t, expectedSeverity.Method, scan.Scanner.Result[i].Severity[j].Method)
					assert.Equal(t, expectedSeverity.Score, scan.Scanner.Result[i].Severity[j].Score)
				}
			}

			// verify valid JSON
			data, err := scan.Generate()
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			// verify generated JSON matches expected struct
			var generatedScan DependencyScan
			err = json.Unmarshal(data, &generatedScan)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedScan, &generatedScan)
		})
	}
}
