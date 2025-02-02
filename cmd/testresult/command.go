package testresult

import (
	"fmt"
	"os"

	testresult "gh-attest-util/internal/attestation/testresult"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	var opts testresult.Options
	var outputFile string

	cmd := &cobra.Command{
		Use:   "depscan",
		Short: "Generate dependency scan predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := testresult.NewFromGrypeResults(opts)
			if err != nil {
				return fmt.Errorf("failed to process scan results: %w", err)
			}

			output, err := result.Generate()
			if err != nil {
				return fmt.Errorf("failed to generate predicate: %w", err)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, output, 0600); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
			} else {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(output)); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.ResultsPath, "results-path", "", "Path to Grype results JSON file")
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject being scanned")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject being scanned")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout)")
	cobra.CheckErr(cmd.MarkFlagRequired("results-path"))
	cobra.CheckErr(cmd.MarkFlagRequired("subject-name"))
	cobra.CheckErr(cmd.MarkFlagRequired("digest"))

	return cmd
}
