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
	var outputFile string
	var buildType string
	var permissionType string

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

			// Use values from environment if flags are not set
			if opts.SubjectName == "" {
				if subjectName, ok := ctx.Inputs["subject-name"].(string); ok {
					opts.SubjectName = subjectName
				}
			}

			if opts.Registry == "" {
				if registry, ok := ctx.Inputs["registry"].(string); ok {
					opts.Registry = registry
				} else if buildType == "blob" {
					opts.Registry = "local" // Default for blobs
				}
			}

			// For blobs, get subject-path from inputs if not set
			if buildType == "blob" && opts.SubjectPath == "" {
				if subjectPath, ok := ctx.Inputs["subject-path"].(string); ok {
					opts.SubjectPath = subjectPath
				}
			}

			// Validate required values based on build type
			if opts.SubjectName == "" {
				return fmt.Errorf("subject-name is required (either as flag or in environment)")
			}

			if buildType == "image" {
				if opts.Digest == "" {
					return fmt.Errorf("digest is required for image type (must be provided via --digest flag)")
				}
				if opts.Registry == "" {
					return fmt.Errorf("registry is required for image type (either as flag or in environment)")
				}
			} else if buildType == "blob" {
				if opts.SubjectPath == "" {
					return fmt.Errorf("subject-path is required for blob type (either as flag or in environment)")
				}
			} else {
				return fmt.Errorf("build-type must be either 'image' or 'blob'")
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

			// Write to file if output flag is set, otherwise write to stdout
			if outputFile != "" {
				if err := os.WriteFile(outputFile, output, 0644); err != nil {
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
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject being attested (optional if set in environment)")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject (required for image type)")
	flags.StringVar(&opts.Registry, "registry", "", "Registry containing the subject (optional if set in environment, only for image type)")
	flags.StringVar(&opts.SubjectPath, "subject-path", "", "Path to the subject (optional if set in environment, only for blob type)")
	flags.StringVar(&opts.PolicyRef, "policy-ref", "", "Reference to the policy being applied")
	flags.StringVar(&controlIds, "control-ids", "", "Comma-separated list of control IDs")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout if not specified)")
	flags.StringVar(&buildType, "build-type", "image", "Type of build (image or blob)")
	flags.StringVar(&permissionType, "permission-type", "high", "Type of permissions (high or low)")

	return cmd
}

func newDepscanCmd() *cobra.Command {
	var opts depscan.Options
	var outputFile string

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

			// Write to file if output flag is set, otherwise write to stdout
			if outputFile != "" {
				if err := os.WriteFile(outputFile, output, 0644); err != nil {
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
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout if not specified)")
	cobra.CheckErr(cmd.MarkFlagRequired("results-path"))

	return cmd
}
