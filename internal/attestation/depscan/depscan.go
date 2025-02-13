package depscan

import (
	"encoding/json"
	"fmt"
	"os"
)

const PredicateTypeURI = "https://in-toto.io/attestation/vulns/v0.2"

// represents predicate portion of attestation
type DependencyScan struct {
	Scanner struct {
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
	} `json:"scanner"`
	Metadata struct {
		ScanStartedOn  string `json:"scanStartedOn"`
		ScanFinishedOn string `json:"scanFinishedOn"`
	} `json:"metadata"`
}

type Options struct {
	ResultsPath string
	SubjectName string
	Digest      string
}

func (d *DependencyScan) Generate() ([]byte, error) {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return data, nil
}

func NewFromGrypeResults(opts Options) (*DependencyScan, error) {
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
				Built         string      `json:"built"`
				SchemaVersion json.Number `json:"schemaVersion"`
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

	scan := &DependencyScan{}

	// set scanner info
	scan.Scanner.URI = fmt.Sprintf("https://github.com/anchore/grype/releases/tag/v%s", grypeResults.Descriptor.Version)
	scan.Scanner.Version = grypeResults.Descriptor.Version

	// set db info
	scan.Scanner.DB.URI = grypeResults.Descriptor.Configuration.DB.UpdateURL
	scan.Scanner.DB.Version = grypeResults.Descriptor.DB.SchemaVersion.String()
	scan.Scanner.DB.LastUpdate = grypeResults.Descriptor.DB.Built

	// set scan metadata
	scan.Metadata.ScanStartedOn = grypeResults.Descriptor.DB.Built
	scan.Metadata.ScanFinishedOn = grypeResults.Descriptor.Timestamp

	// process vulnerabilities
	for _, match := range grypeResults.Matches {
		result := struct {
			ID       string `json:"id"`
			Severity []struct {
				Method string `json:"method"`
				Score  string `json:"score"`
			} `json:"severity"`
		}{
			ID: match.Vulnerability.ID,
			Severity: []struct {
				Method string `json:"method"`
				Score  string `json:"score"`
			}{
				{
					Method: "nvd",
					Score:  match.Vulnerability.Severity,
				},
			},
		}

		// if available, add CVSS score
		if len(match.Vulnerability.CVSS) > 0 {
			result.Severity = append(result.Severity, struct {
				Method string `json:"method"`
				Score  string `json:"score"`
			}{
				Method: "cvss_score",
				Score:  fmt.Sprintf("%.1f", match.Vulnerability.CVSS[0].Metrics.BaseScore),
			})
		}

		scan.Scanner.Result = append(scan.Scanner.Result, result)
	}

	return scan, nil
}
