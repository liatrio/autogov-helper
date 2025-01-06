package depscan

import (
	"encoding/json"
	"fmt"
	"os"
)

const PredicateTypeURI = "https://liatr.io/attestations/dependency-scan/v1"

type DependencyScan struct {
	Scanner struct {
		URI     string `json:"uri"`
		Version string `json:"version"`
		DB      struct {
			URI        string `json:"uri"`
			Version    string `json:"version"`
			LastUpdate string `json:"lastUpdate"`
		} `json:"db"`
		Result []Vulnerability `json:"result"`
	} `json:"scanner"`
	Metadata struct {
		ScanStartedOn  string `json:"scanStartedOn"`
		ScanFinishedOn string `json:"scanFinishedOn"`
	} `json:"metadata"`
}

type Vulnerability struct {
	ID       string     `json:"id"`
	Severity []Severity `json:"severity"`
}

type Severity struct {
	Method string `json:"method"`
	Score  string `json:"score"`
}

func (d *DependencyScan) Type() string {
	return PredicateTypeURI
}

func (d *DependencyScan) Generate() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

type Options struct {
	ResultsPath string
}

// NewFromGrypeResults creates a new DependencyScan from Grype results
func NewFromGrypeResults(opts Options) (*DependencyScan, error) {
	resultsData, err := os.ReadFile(opts.ResultsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	var grypeResults struct {
		Descriptor struct {
			Version       string `json:"version"`
			Configuration struct {
				DB struct {
					UpdateURL string `json:"update-url"`
				} `json:"db"`
			} `json:"configuration"`
			DB struct {
				SchemaVersion string `json:"schemaVersion"`
				Built         string `json:"built"`
			} `json:"db"`
			Timestamp string `json:"timestamp"`
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

	// Set scanner info
	scan.Scanner.URI = fmt.Sprintf("https://github.com/anchore/grype/releases/tag/v%s", grypeResults.Descriptor.Version)
	scan.Scanner.Version = grypeResults.Descriptor.Version
	scan.Scanner.DB.URI = grypeResults.Descriptor.Configuration.DB.UpdateURL
	scan.Scanner.DB.Version = grypeResults.Descriptor.DB.SchemaVersion
	scan.Scanner.DB.LastUpdate = grypeResults.Descriptor.DB.Built

	// Set metadata
	scan.Metadata.ScanStartedOn = grypeResults.Descriptor.DB.Built
	scan.Metadata.ScanFinishedOn = grypeResults.Descriptor.Timestamp

	// Process vulnerabilities
	for _, match := range grypeResults.Matches {
		vuln := Vulnerability{
			ID: match.Vulnerability.ID,
			Severity: []Severity{
				{
					Method: "nvd",
					Score:  match.Vulnerability.Severity,
				},
			},
		}

		if len(match.Vulnerability.CVSS) > 0 {
			vuln.Severity = append(vuln.Severity, Severity{
				Method: "cvss_score",
				Score:  fmt.Sprintf("%.1f", match.Vulnerability.CVSS[0].Metrics.BaseScore),
			})
		}

		scan.Scanner.Result = append(scan.Scanner.Result, vuln)
	}

	return scan, nil
}
