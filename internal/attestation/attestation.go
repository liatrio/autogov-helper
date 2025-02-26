package attestation

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"autogov-helper/internal/config"
	"autogov-helper/internal/types"
	"autogov-helper/internal/util/errors"
)

// options for metadata attestations
type MetadataOptions = types.Options

// options for depscan attestations
type DepscanOptions = types.DependencyScanOptions

// write output to file or stdout
func writeOutput(output []byte, outputFile string) error {
	if outputFile != "" {
		if err := os.WriteFile(outputFile, output, 0600); err != nil {
			return errors.WrapError("write output file", err)
		}
	} else {
		fmt.Println(string(output))
	}
	return nil
}

// generate metadata attestation
func GenerateMetadata(opts types.Options, outputFile string) error {
	m := types.NewFromOptions(opts)

	// validate input
	if opts.Type != types.ArtifactTypeContainerImage && opts.Type != types.ArtifactTypeBlob {
		return fmt.Errorf("invalid artifact type: %s", opts.Type)
	}

	if opts.Type == types.ArtifactTypeContainerImage {
		if opts.Registry == "" || opts.FullName == "" || opts.Digest == "" {
			return fmt.Errorf("container-image requires registry, fullName, and digest fields")
		}
	}

	if opts.Type == types.ArtifactTypeBlob && opts.SubjectPath == "" {
		return fmt.Errorf("blob requires subjectPath field")
	}

	output, err := m.Generate()
	if err != nil {
		return errors.WrapError("generate predicate", err)
	}

	// validate against schema
	if err := config.ValidateMetadata(output); err != nil {
		return errors.WrapError("validate metadata", err)
	}

	return writeOutput(output, outputFile)
}

// generate depscan attestation
func GenerateDepscan(opts types.DependencyScanOptions, outputFile string) error {
	// read results
	data, err := os.ReadFile(opts.ResultsPath)
	if err != nil {
		return errors.WrapError("read results file", err)
	}

	// parse results
	var results types.GrypeResult
	if err := json.Unmarshal(data, &results); err != nil {
		return errors.WrapError("parse results", err)
	}

	// set timestamps
	opts.StartedAt = time.Now()
	opts.FinishedAt = time.Now()

	// create scan
	scan := types.NewDependencyScan(opts)

	// set scanner info
	scan.Scanner.Name = "grype"
	scan.Scanner.Version = results.Descriptor.Version
	scan.Scanner.URI = fmt.Sprintf("https://github.com/anchore/grype/releases/tag/v%s", results.Descriptor.Version)

	// set db info
	scan.Scanner.DB.URI = results.Descriptor.Configuration.DB.UpdateURL
	scan.Scanner.DB.Version = string(results.Descriptor.DB.SchemaVersion)
	scan.Scanner.DB.LastUpdate = results.Descriptor.DB.Built

	// convert results
	for _, match := range results.Matches {
		result := types.ScanResult{
			ID: match.Vulnerability.ID,
			Severity: []types.Severity{
				{
					Method: "nvd",
					Score:  match.Vulnerability.Severity,
				},
			},
		}

		// add cvss score if available
		if len(match.Vulnerability.CVSS) > 0 {
			result.Severity = append(result.Severity, types.Severity{
				Method: "cvss_score",
				Score:  fmt.Sprintf("%.1f", match.Vulnerability.CVSS[0].Metrics.BaseScore),
			})
		}

		scan.Scanner.Result = append(scan.Scanner.Result, result)
	}

	// generate output
	output, err := scan.Generate()
	if err != nil {
		return errors.WrapError("generate predicate", err)
	}

	// validate against schema
	if err := config.ValidateDepscan(output); err != nil {
		return errors.WrapError("validate depscan", err)
	}

	return writeOutput(output, outputFile)
}
