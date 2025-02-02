package testresult

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
		testData       string
		expectedResult *TestResult
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
			expectedResult: &TestResult{
				Result: "WARNED",
				Configuration: []ResourceDescriptor{
					{
						Name:             "grype",
						DownloadLocation: "https://github.com/anchore/grype/releases/tag/v0.87.0",
						Digest: map[string]string{
							"version":   "0.87.0",
							"dbVersion": "5",
							"dbBuilt":   "2025-01-23T01:31:43Z",
						},
					},
				},
				URL:         "https://toolbox-data.anchore.io/grype/databases/listing.json",
				WarnedTests: []string{"vulnerability-CVE-2024-1234"},
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

			result, err := NewFromGrypeResults(opts)
			assert.NoError(t, err)
			assert.NotNil(t, result)

			// verify configuration
			assert.Equal(t, tc.expectedResult.Configuration, result.Configuration)
			assert.Equal(t, tc.expectedResult.URL, result.URL)

			// verify test results
			assert.Equal(t, tc.expectedResult.Result, result.Result)
			assert.Equal(t, tc.expectedResult.PassedTests, result.PassedTests)
			assert.Equal(t, tc.expectedResult.WarnedTests, result.WarnedTests)
			assert.Equal(t, tc.expectedResult.FailedTests, result.FailedTests)

			// verify subject fields
			assert.Equal(t, "test-subject", result.SubjectName)
			assert.Equal(t, "test-digest", result.Digest)

			// verify valid JSON
			data, err := result.Generate()
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			var statement struct {
				Type          string      `json:"_type"`
				Subject       []Subject   `json:"subject"`
				PredicateType string      `json:"predicateType"`
				Predicate     *TestResult `json:"predicate"`
			}
			err = json.Unmarshal(data, &statement)
			assert.NoError(t, err)

			// verify statement structure
			assert.Equal(t, "https://in-toto.io/Statement/v1", statement.Type)
			assert.Equal(t, PredicateTypeURI, statement.PredicateType)

			// verify subject
			require.Len(t, statement.Subject, 1)
			assert.Equal(t, "test-subject", statement.Subject[0].Name)
			assert.Equal(t, "test-digest", statement.Subject[0].Digest["sha256"])

			// verify predicate matches expected
			assert.Equal(t, tc.expectedResult, statement.Predicate)
		})
	}
}
