package testresult

import (
	"encoding/json"
	"fmt"
	"os"
)

const PredicateTypeURI = "https://in-toto.io/attestation/test-result/v0.1"

// represents predicate portion of attestation using test-result schema
type TestResult struct {
	Result        string               `json:"result"`
	Configuration []ResourceDescriptor `json:"configuration"`
	URL           string               `json:"url,omitempty"`
	PassedTests   []string             `json:"passedTests,omitempty"`
	WarnedTests   []string             `json:"warnedTests,omitempty"`
	FailedTests   []string             `json:"failedTests,omitempty"`
	SubjectName   string               `json:"-"`
	Digest        string               `json:"-"`
}

type ResourceDescriptor struct {
	Name             string            `json:"name"`
	DownloadLocation string            `json:"downloadLocation"`
	Digest           map[string]string `json:"digest"`
}

type Options struct {
	ResultsPath string
	SubjectName string
	Digest      string
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

func (t *TestResult) Generate() ([]byte, error) {
	statement := struct {
		Type          string      `json:"_type"`
		Subject       []Subject   `json:"subject"`
		PredicateType string      `json:"predicateType"`
		Predicate     *TestResult `json:"predicate"`
	}{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: PredicateTypeURI,
		Predicate:     t,
		Subject: []Subject{
			{
				Name: t.SubjectName,
				Digest: map[string]string{
					"sha256": t.Digest,
				},
			},
		},
	}

	data, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return nil, err
	}
	return data, nil
}

func NewFromGrypeResults(opts Options) (*TestResult, error) {
	resultsData, err := os.ReadFile(opts.ResultsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	var grypeResults struct {
		Descriptor struct {
			Version       string `json:"version"`
			Timestamp     string `json:"timestamp"`
			Configuration struct {
				DB struct {
					UpdateURL string `json:"update-url"`
				} `json:"db"`
			} `json:"configuration"`
			DB struct {
				Built         string `json:"built"`
				SchemaVersion string `json:"schemaVersion"`
			} `json:"db"`
		} `json:"descriptor"`
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				CVSS     []struct {
					Metrics struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"metrics"`
				} `json:"cvss"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}

	if err := json.Unmarshal(resultsData, &grypeResults); err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	result := &TestResult{
		Configuration: []ResourceDescriptor{
			{
				Name:             "grype",
				DownloadLocation: fmt.Sprintf("https://github.com/anchore/grype/releases/tag/v%s", grypeResults.Descriptor.Version),
				Digest: map[string]string{
					"version":   grypeResults.Descriptor.Version,
					"dbVersion": grypeResults.Descriptor.DB.SchemaVersion,
					"dbBuilt":   grypeResults.Descriptor.DB.Built,
				},
			},
		},
		URL:         grypeResults.Descriptor.Configuration.DB.UpdateURL,
		SubjectName: opts.SubjectName,
		Digest:      opts.Digest,
	}

	// Process vulnerabilities into test results
	for _, match := range grypeResults.Matches {
		testName := fmt.Sprintf("vulnerability-%s", match.Vulnerability.ID)

		// Determine severity level
		switch match.Vulnerability.Severity {
		case "Critical", "High":
			result.FailedTests = append(result.FailedTests, testName)
		case "Medium":
			result.WarnedTests = append(result.WarnedTests, testName)
		default:
			result.PassedTests = append(result.PassedTests, testName)
		}
	}

	// Set overall result based on presence of failures
	if len(result.FailedTests) > 0 {
		result.Result = "FAILED"
	} else if len(result.WarnedTests) > 0 {
		result.Result = "WARNED"
	} else {
		result.Result = "PASSED"
	}

	return result, nil
}
