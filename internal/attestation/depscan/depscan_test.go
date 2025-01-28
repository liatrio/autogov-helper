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
		name           string
		artifactType   string
		highPermission bool
		testData       string
		expectedScan   *DependencyScan
	}{
		{
			name:           "blob_high_permissions",
			artifactType:   "blob",
			highPermission: true,
			testData: `{
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
			}`,
			expectedScan: &DependencyScan{
				Scanner: struct {
					URI     string `json:"uri"`
					Version string `json:"version"`
					Db      struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					} `json:"db"`
					Result []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					} `json:"result"`
				}{
					URI:     "https://github.com/anchore/grype/releases/tag/v0.74.7",
					Version: "0.74.7",
					Db: struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					}{
						Name:        "grype",
						Version:     "1.5",
						LastUpdated: "2024-03-14T12:00:00Z",
					},
					Result: []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					}{
						{
							ID: "CVE-2024-1234",
							Severity: struct {
								Method string `json:"method"`
								Score  string `json:"score"`
							}{
								Method: "CVSSv3",
								Score:  "7.5",
							},
						},
					},
				},
			},
		},
		{
			name:           "blob_low_permissions",
			artifactType:   "blob",
			highPermission: false,
			testData: `{
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
			}`,
			expectedScan: &DependencyScan{
				Scanner: struct {
					URI     string `json:"uri"`
					Version string `json:"version"`
					Db      struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					} `json:"db"`
					Result []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					} `json:"result"`
				}{
					URI:     "https://github.com/anchore/grype/releases/tag/v0.74.7",
					Version: "0.74.7",
					Db: struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					}{
						Name:        "grype",
						Version:     "1.5",
						LastUpdated: "2024-03-14T12:00:00Z",
					},
					Result: []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					}{
						{
							ID: "CVE-2024-1234",
							Severity: struct {
								Method string `json:"method"`
								Score  string `json:"score"`
							}{
								Method: "CVSSv3",
								Score:  "7.5",
							},
						},
					},
				},
			},
		},
		{
			name:           "container_image_high_permissions",
			artifactType:   "container-image",
			highPermission: true,
			testData: `{
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
			}`,
			expectedScan: &DependencyScan{
				Scanner: struct {
					URI     string `json:"uri"`
					Version string `json:"version"`
					Db      struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					} `json:"db"`
					Result []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					} `json:"result"`
				}{
					URI:     "https://github.com/anchore/grype/releases/tag/v0.74.7",
					Version: "0.74.7",
					Db: struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					}{
						Name:        "grype",
						Version:     "1.5",
						LastUpdated: "2024-03-14T12:00:00Z",
					},
					Result: []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					}{
						{
							ID: "CVE-2024-1234",
							Severity: struct {
								Method string `json:"method"`
								Score  string `json:"score"`
							}{
								Method: "CVSSv3",
								Score:  "7.5",
							},
						},
					},
				},
			},
		},
		{
			name:           "container_image_low_permissions",
			artifactType:   "container-image",
			highPermission: false,
			testData: `{
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
			}`,
			expectedScan: &DependencyScan{
				Scanner: struct {
					URI     string `json:"uri"`
					Version string `json:"version"`
					Db      struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					} `json:"db"`
					Result []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					} `json:"result"`
				}{
					URI:     "https://github.com/anchore/grype/releases/tag/v0.74.7",
					Version: "0.74.7",
					Db: struct {
						Name        string `json:"name"`
						Version     string `json:"version"`
						LastUpdated string `json:"lastUpdated"`
					}{
						Name:        "grype",
						Version:     "1.5",
						LastUpdated: "2024-03-14T12:00:00Z",
					},
					Result: []struct {
						ID       string `json:"id"`
						Severity struct {
							Method string `json:"method"`
							Score  string `json:"score"`
						} `json:"severity"`
					}{
						{
							ID: "CVE-2024-1234",
							Severity: struct {
								Method string `json:"method"`
								Score  string `json:"score"`
							}{
								Method: "CVSSv3",
								Score:  "7.5",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary file with test data
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

			// Verify scanner fields
			assert.Equal(t, tc.expectedScan.Scanner.URI, scan.Scanner.URI)
			assert.Equal(t, tc.expectedScan.Scanner.Version, scan.Scanner.Version)

			// Verify DB fields
			assert.Equal(t, tc.expectedScan.Scanner.Db.Name, scan.Scanner.Db.Name)
			assert.Equal(t, tc.expectedScan.Scanner.Db.Version, scan.Scanner.Db.Version)
			assert.Equal(t, tc.expectedScan.Scanner.Db.LastUpdated, scan.Scanner.Db.LastUpdated)

			// Verify results
			require.Equal(t, len(tc.expectedScan.Scanner.Result), len(scan.Scanner.Result))
			for i, expectedResult := range tc.expectedScan.Scanner.Result {
				assert.Equal(t, expectedResult.ID, scan.Scanner.Result[i].ID)
				assert.Equal(t, expectedResult.Severity.Method, scan.Scanner.Result[i].Severity.Method)
				assert.Equal(t, expectedResult.Severity.Score, scan.Scanner.Result[i].Severity.Score)
			}

			// Verify we can generate valid JSON
			data, err := scan.Generate()
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			// Verify the generated JSON matches our expected structure
			var generatedScan DependencyScan
			err = json.Unmarshal(data, &generatedScan)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedScan, &generatedScan)
		})
	}
}
