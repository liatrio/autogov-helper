package metadata

import (
	"fmt"
	"os"

	"gh-attest-util/internal/attestation/metadata"
	"gh-attest-util/internal/github"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	var opts metadata.Options
	var controlIds string
	var outputFile string
	var buildType string

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate metadata predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := github.LoadFromEnv()
			if err != nil {
				return fmt.Errorf("failed to load GitHub context: %w", err)
			}

			// use env vars if flags are not set
			if opts.SubjectName == "" {
				if subjectName, ok := ctx.Inputs["subject-name"].(string); ok {
					opts.SubjectName = subjectName
				}
			}

			if opts.Registry == "" {
				if registry, ok := ctx.Inputs["registry"].(string); ok {
					opts.Registry = registry
				} else if buildType == "blob" {
					opts.Registry = "local" // default for blobs
				}
			}

			// for blobs, get subject-path from inputs if not set
			if buildType == "blob" && opts.SubjectPath == "" {
				if subjectPath, ok := ctx.Inputs["subject-path"].(string); ok {
					opts.SubjectPath = subjectPath
				}
			}

			// validate required values based on build type
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
				opts.ControlIds = append(opts.ControlIds, controlIds)
			}

			m, err := metadata.NewFromGitHubContext(ctx, opts)
			if err != nil {
				return fmt.Errorf("failed to create metadata: %w", err)
			}

			output, err := m.Generate()
			if err != nil {
				return fmt.Errorf("failed to generate metadata: %w", err)
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
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject being attested")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject (required for image type)")
	flags.StringVar(&opts.Registry, "registry", "", "Registry containing the subject (optional if set in environment)")
	flags.StringVar(&opts.SubjectPath, "subject-path", "", "Path to the subject (required for blob type)")
	flags.StringVar(&opts.PolicyRef, "policy-ref", "", "Reference to the policy being applied")
	flags.StringVar(&controlIds, "control-ids", "", "Comma-separated list of control IDs")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&buildType, "build-type", "image", "Type of build (image or blob)")

	return cmd
}
