package main

import (
	"fmt"
	"os"
	"strings"

	"gh-attest-util/internal/attestation/depscan"
	"gh-attest-util/internal/attestation/metadata"
	"gh-attest-util/internal/github"

	"github.com/spf13/cobra"
)

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gh-attest-util",
		Short: "GitHub Attestation Utility",
		Long:  "A utility for generating custom predicates for GitHub Actions attestations",
	}

	cmd.AddCommand(newMetadataCmd(), newDepscanCmd())
	return cmd
}

func newMetadataCmd() *cobra.Command {
	var opts metadata.Options
	var controlIds string

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate metadata predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := github.LoadFromEnv()
			if err != nil {
				return fmt.Errorf("failed to load GitHub context: %w", err)
			}

			runner, err := github.LoadRunnerFromEnv()
			if err != nil {
				return fmt.Errorf("failed to load runner context: %w", err)
			}

			if controlIds != "" {
				opts.ControlIds = strings.Split(controlIds, ",")
			}

			m, err := metadata.NewFromGitHubContext(ctx, runner, opts)
			if err != nil {
				return fmt.Errorf("failed to create metadata: %w", err)
			}

			output, err := m.Generate()
			if err != nil {
				return fmt.Errorf("failed to generate metadata: %w", err)
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(output))
			if err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject being attested")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject")
	flags.StringVar(&opts.Registry, "registry", "", "Registry containing the subject")
	flags.StringVar(&opts.PolicyRef, "policy-ref", "", "Reference to the policy being applied")
	flags.StringVar(&controlIds, "control-ids", "", "Comma-separated list of control IDs")

	cobra.CheckErr(cmd.MarkFlagRequired("subject-name"))
	cobra.CheckErr(cmd.MarkFlagRequired("digest"))
	cobra.CheckErr(cmd.MarkFlagRequired("registry"))

	return cmd
}

func newDepscanCmd() *cobra.Command {
	var opts depscan.Options

	cmd := &cobra.Command{
		Use:   "depscan",
		Short: "Generate dependency scan predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			scan, err := depscan.NewFromGrypeResults(opts)
			if err != nil {
				return fmt.Errorf("failed to process scan results: %w", err)
			}

			output, err := scan.Generate()
			if err != nil {
				return fmt.Errorf("failed to generate predicate: %w", err)
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(output))
			if err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.ResultsPath, "results-path", "", "Path to Grype results JSON file")
	cobra.CheckErr(cmd.MarkFlagRequired("results-path"))

	return cmd
}
