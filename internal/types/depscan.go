package types

import (
	"encoding/json"
	"time"
)

const DepscanPredicateTypeURI = "https://in-toto.io/attestation/vulns/v0.2"

// predicate portion of a dependency scan attestation
type DependencyScan struct {
	Type        ArtifactType `json:"-"`
	SubjectName string       `json:"-"`
	SubjectPath string       `json:"-"`
	Digest      string       `json:"-"`
	Scanner     struct {
		Name    string `json:"name"`
		URI     string `json:"uri"`
		Version string `json:"version"`
		DB      struct {
			URI        string `json:"uri"`
			Version    string `json:"version"`
			LastUpdate string `json:"lastUpdate"`
		} `json:"db"`
		Result []ScanResult `json:"result"`
	} `json:"scanner"`
	Metadata struct {
		ScanStartedOn  string `json:"scanStartedOn"`
		ScanFinishedOn string `json:"scanFinishedOn"`
	} `json:"metadata,omitempty"`
}

// generates json representation of predicate
func (s *DependencyScan) Generate() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// options for creating a new scan
type DependencyScanOptions struct {
	Type        ArtifactType
	SubjectName string
	SubjectPath string
	Digest      string
	ResultsPath string
	StartedAt   time.Time
	FinishedAt  time.Time
}

// grype scan results
type GrypeResult struct {
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

// single vulnerability finding
type ScanResult struct {
	ID       string     `json:"id"`
	Severity []Severity `json:"severity"`
}

// vulnerability severity score
type Severity struct {
	Method string `json:"method"`
	Score  string `json:"score"`
}

// creates new scan instance
func NewDependencyScan(opts DependencyScanOptions) *DependencyScan {
	scan := &DependencyScan{
		Type:        opts.Type,
		SubjectName: opts.SubjectName,
		SubjectPath: opts.SubjectPath,
		Digest:      opts.Digest,
	}

	// initialize empty result array
	scan.Scanner.Result = make([]ScanResult, 0)

	// set metadata timestamps
	scan.Metadata.ScanStartedOn = opts.StartedAt.Format("2006-01-02T15:04:05Z")
	scan.Metadata.ScanFinishedOn = opts.FinishedAt.Format("2006-01-02T15:04:05Z")

	return scan
}
