package generate

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gh-attest-util/internal/attestation/vsa"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate attestations",
	}

	cmd.AddCommand(
		newVSACommand(),
		newMetadataCommand(),
		newTestResultCommand(),
	)

	return cmd
}

func newVSACommand() *cobra.Command {
	var (
		subjectName   string
		subjectDigest string
		verifierID    string
		resourceURI   string
		level         string
		slsaVersion   string
		outputPath    string
	)

	cmd := &cobra.Command{
		Use:   "vsa",
		Short: "Generate a Verification Summary Attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := vsa.Options{
				SubjectName:   subjectName,
				SubjectDigest: subjectDigest,
				VerifierID:    verifierID,
				Result:        "PASSED",
				Levels:        []string{level},
				ResourceURI:   resourceURI,
				SlsaVersion:   slsaVersion,
				TimeVerified:  time.Now().UTC(),
			}

			attestation, err := vsa.New(opts)
			if err != nil {
				return fmt.Errorf("failed to create VSA: %w", err)
			}

			data, err := json.MarshalIndent(attestation, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal VSA: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, data, 0644); err != nil {
					return fmt.Errorf("failed to write VSA to file: %w", err)
				}
			} else {
				fmt.Println(string(data))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&subjectName, "subject-name", "", "name of the artifact being verified")
	cmd.Flags().StringVar(&subjectDigest, "subject-digest", "", "digest of the artifact (sha256:...)")
	cmd.Flags().StringVar(&verifierID, "verifier-id", "", "ID of the verifier")
	cmd.Flags().StringVar(&resourceURI, "resource-uri", "", "URI of the resource being verified")
	cmd.Flags().StringVar(&level, "level", "SLSA_BUILD_LEVEL_3", "SLSA build level")
	cmd.Flags().StringVar(&slsaVersion, "slsa-version", "1.0", "SLSA version")
	cmd.Flags().StringVar(&outputPath, "output", "", "path to write the VSA (default stdout)")

	cmd.MarkFlagRequired("subject-name")
	cmd.MarkFlagRequired("subject-digest")
	cmd.MarkFlagRequired("verifier-id")
	cmd.MarkFlagRequired("resource-uri")

	return cmd
}

func newMetadataCommand() *cobra.Command {
	var (
		name       string
		version    string
		buildType  string
		buildID    string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate a metadata attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			metadata := map[string]interface{}{
				"name":      name,
				"version":   version,
				"buildType": buildType,
				"buildId":   buildID,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			}

			data, err := json.MarshalIndent(metadata, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal metadata: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, data, 0644); err != nil {
					return fmt.Errorf("failed to write metadata to file: %w", err)
				}
			} else {
				fmt.Println(string(data))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of the artifact")
	cmd.Flags().StringVar(&version, "version", "", "version of the artifact")
	cmd.Flags().StringVar(&buildType, "build-type", "", "type of build")
	cmd.Flags().StringVar(&buildID, "build-id", "", "build identifier")
	cmd.Flags().StringVar(&outputPath, "output", "", "path to write the metadata (default stdout)")

	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("version")
	cmd.MarkFlagRequired("build-type")
	cmd.MarkFlagRequired("build-id")

	return cmd
}

func newTestResultCommand() *cobra.Command {
	var (
		name       string
		result     string
		details    string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "testresult",
		Short: "Generate a test result attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			testResult := map[string]interface{}{
				"name":      name,
				"result":    result,
				"details":   details,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			}

			data, err := json.MarshalIndent(testResult, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal test result: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, data, 0644); err != nil {
					return fmt.Errorf("failed to write test result to file: %w", err)
				}
			} else {
				fmt.Println(string(data))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of the test")
	cmd.Flags().StringVar(&result, "result", "", "test result (pass/fail)")
	cmd.Flags().StringVar(&details, "details", "", "test details")
	cmd.Flags().StringVar(&outputPath, "output", "", "path to write the test result (default stdout)")

	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("result")

	return cmd
} 