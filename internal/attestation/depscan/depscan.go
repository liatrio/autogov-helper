package depscan

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gh-attest-util/internal/attestation/schema/generated"

	"github.com/CycloneDX/cyclonedx-go"
)

const PredicateTypeURI = "https://in-toto.io/attestation/vulns/v0.2"

type DependencyScan struct {
	generated.Dependencyscan
}

type Options struct {
	ResultsPath string
	SubjectName string
	Digest      string
}

func (d *DependencyScan) Type() string {
	return PredicateTypeURI
}

func (d *DependencyScan) Generate() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func NewFromGrypeResults(opts Options) (*DependencyScan, error) {
	resultsData, err := os.ReadFile(opts.ResultsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	var grypeResults cyclonedx.BOM
	if err := json.Unmarshal(resultsData, &grypeResults); err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	scan := &DependencyScan{
		Dependencyscan: generated.Dependencyscan{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: PredicateTypeURI,
			Subject: []generated.Subject{
				{
					Name: opts.SubjectName,
					Digest: struct {
						SHA256 string `json:"sha256"`
					}{
						SHA256: opts.Digest,
					},
				},
			},
		},
	}

	if grypeResults.Metadata != nil && grypeResults.Metadata.Tools != nil {
		tools := grypeResults.Metadata.Tools.Tools
		if tools != nil && len(*tools) > 0 {
			toolList := *tools
			tool := toolList[0]
			scan.Predicate.Scanner.URI = fmt.Sprintf("https://github.com/%s/%s/releases/tag/v%s", tool.Vendor, tool.Name, tool.Version)
			scan.Predicate.Scanner.Version = tool.Version
		}
	}

	scan.Predicate.Scanner.DB.Name = "grype"
	scan.Predicate.Scanner.DB.Version = grypeResults.SpecVersion.String()
	if grypeResults.Metadata != nil {
		if t, err := time.Parse(time.RFC3339, grypeResults.Metadata.Timestamp); err == nil {
			scan.Predicate.Scanner.DB.LastUpdated = t.Format(time.RFC3339)
		}
	}

	if grypeResults.Vulnerabilities != nil {
		for _, vuln := range *grypeResults.Vulnerabilities {
			result := struct {
				ID       string `json:"id"`
				Severity struct {
					Method string `json:"method"`
					Score  string `json:"score"`
				} `json:"severity"`
			}{
				ID: vuln.ID,
			}

			if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
				ratings := *vuln.Ratings
				rating := ratings[0]
				result.Severity.Method = string(rating.Method)
				if rating.Score != nil {
					result.Severity.Score = fmt.Sprintf("%.1f", *rating.Score)
				} else {
					result.Severity.Score = string(rating.Severity)
				}
			} else if vuln.Source != nil {
				result.Severity.Method = vuln.Source.Name
				result.Severity.Score = "UNKNOWN"
			}

			scan.Predicate.Scanner.Result = append(scan.Predicate.Scanner.Result, result)
		}
	}

	return scan, nil
}
