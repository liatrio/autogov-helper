package vsa

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gh-attest-util/internal/attestation/vsa"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	var (
		// verify
		vsaPath       string
		expectedLevel int
		
		// generate
		subjectName   string
		subjectDigest string
		verifierID    string
		result        string
		levels        []string
		resourceURI   string
		slsaVersion   string
		
		// shared
		outputFile    string
	)

	cmd := &cobra.Command{
		Use:   "vsa",
		Short: "Work with VSA attestations (generate/verify)",
		Example: `  # Generate a VSA:
  gh-attest-util vsa generate --subject-name my-image --digest sha256:abc123... --verifier-id gha-verifier-v1 --result PASSED --levels SLSA_BUILD_LEVEL_3 --output vsa.json

  # Verify a VSA:
  gh-attest-util vsa verify --vsa vsa.json --level 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("must specify either 'generate' or 'verify' subcommand")
		},
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new VSA",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := vsa.Options{
				SubjectName:     subjectName,
				SubjectDigest:   subjectDigest,
				VerifierID:      verifierID,
				Result:          result,
				Levels:          levels,
				ResourceURI:     resourceURI,
				SlsaVersion:     slsaVersion,
				TimeVerified:    time.Now().UTC(),
			}

			vsaObj, err := vsa.New(opts)
			if err != nil {
				return fmt.Errorf("failed to generate VSA: %w", err)
			}
			jsonData, err := json.MarshalIndent(vsaObj, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal VSA: %w", err)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, jsonData, 0600); err != nil {
					return fmt.Errorf("failed to write VSA: %w", err)
				}
			} else {
				fmt.Println(string(jsonData))
			}
			return nil
		},
	}

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an existing VSA",
		RunE: func(cmd *cobra.Command, args []string) error {
			vsaData, err := os.ReadFile(vsaPath)
			if err != nil {
				return fmt.Errorf("failed to read VSA file: %w", err)
			}

			vsaObj, err := vsa.NewVSAFromBytes(vsaData)
			if err != nil {
				return fmt.Errorf("failed to parse VSA: %w", err)
			}

			if err := vsaObj.VerifyBuildLevel(expectedLevel); err != nil {
				return fmt.Errorf("VSA verification failed: %w", err)
			}

			return nil
		},
	}

	cmd.AddCommand(generateCmd, verifyCmd)

	generateCmd.Flags().StringVar(&subjectName, "name", "", "Name of the subject being attested")
	generateCmd.Flags().StringVar(&subjectDigest, "digest", "", "SHA256 digest of the subject")
	generateCmd.Flags().StringVar(&verifierID, "verifier", "", "ID of the verifier tool/process")
	generateCmd.Flags().StringVar(&result, "result", "PASSED", "Verification result (PASSED/FAILED)")
	generateCmd.Flags().StringSliceVar(&levels, "levels", []string{}, "SLSA levels achieved (comma separated)")
	generateCmd.Flags().StringVar(&resourceURI, "uri", "", "URI of the resource being verified")
	generateCmd.Flags().StringVar(&slsaVersion, "slsa", "v1.0", "SLSA specification version used")
	generateCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	verifyCmd.Flags().StringVarP(&vsaPath, "vsa", "v", "", "Path to VSA file")
	verifyCmd.Flags().IntVarP(&expectedLevel, "level", "l", 3, "Expected SLSA build level (L0-L3)")

	if err := generateCmd.MarkFlagRequired("name"); err != nil {
		panic(fmt.Sprintf("failed to mark flag as required: %v", err))
	}
	if err := generateCmd.MarkFlagRequired("digest"); err != nil {
		panic(fmt.Sprintf("failed to mark flag as required: %v", err))
	}
	if err := generateCmd.MarkFlagRequired("verifier"); err != nil {
		panic(fmt.Sprintf("failed to mark flag as required: %v", err))
	}
	if err := verifyCmd.MarkFlagRequired("vsa"); err != nil {
		panic(fmt.Sprintf("failed to mark flag as required: %v", err))
	}

	generateCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if result != "PASSED" && result != "FAILED" {
			return fmt.Errorf("--result must be either PASSED or FAILED")
		}
		if len(levels) == 0 {
			return fmt.Errorf("--levels is required")
		}
		return nil
	}

	verifyCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if expectedLevel < 0 || expectedLevel > 3 {
			return fmt.Errorf("invalid SLSA build level %d: must be between 0-3", expectedLevel)
		}
		return nil
	}

	return cmd
}
