package metadata

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gh-attest-util/internal/attestation/metadata"
	"gh-attest-util/internal/github"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	var opts metadata.Options
	var outputFile string
	var buildType string

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate metadata predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := github.LoadFromEnv()
			if err != nil {
				return fmt.Errorf("failed to get GitHub context: %w", err)
			}

			now := time.Now().UTC()
			shortSHA := ctx.SHA
			if len(shortSHA) > 7 && shortSHA != "test-sha" {
				shortSHA = shortSHA[:7]
			}

			// Set artifact details
			opts.Version = fmt.Sprintf("%s-%s", shortSHA, ctx.RunNumber)
			opts.Created = now
			opts.Type = metadata.ArtifactTypeContainerImage
			if buildType == "blob" {
				opts.Type = metadata.ArtifactTypeBlob
			}

			// Set repository details
			opts.Repository = ctx.Repository
			opts.GitHubServerURL = ctx.ServerURL

			// Set owner details
			opts.Owner = ctx.RepositoryOwner

			// Set runner details
			opts.OS = ctx.Runner.OS
			opts.Name = ctx.Runner.Environment

			// Set workflow details
			opts.WorkflowName = filepath.Base(ctx.WorkflowRef)
			opts.WorkflowRefPath = ctx.WorkflowRef
			opts.RunID = ctx.RunID

			// Set job details
			opts.JobName = ctx.JobStatus

			// Set commit details
			opts.SHA = ctx.SHA
			opts.Message = ctx.Event.HeadCommit.Timestamp
			opts.Author = ctx.Actor
			opts.URL = fmt.Sprintf("%s/%s/commit/%s", ctx.ServerURL, ctx.Repository, ctx.SHA)

			if buildType == "blob" {
				if opts.SubjectPath == "" {
					return fmt.Errorf("subject-path is required for blob type")
				}
				subjectPath := opts.SubjectPath
				if _, err := os.Stat(subjectPath); err != nil {
					return fmt.Errorf("failed to read subject file: %w", err)
				}
				opts.SubjectPath = subjectPath
				// If subject-name is not provided for blobs, use the filename
				if opts.SubjectName == "" {
					opts.SubjectName = filepath.Base(subjectPath)
				}
			} else if opts.SubjectName == "" {
				return fmt.Errorf("subject-name is required for container-image type")
			}

			m, err := metadata.NewFromOptions(opts)
			if err != nil {
				return fmt.Errorf("failed to generate metadata: %w", err)
			}

			output, err := m.Generate()
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
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject being attested")
	flags.StringVar(&opts.SubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject being attested")
	flags.StringVar(&buildType, "type", "container-image", "Type of build (container-image or blob)")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout)")
	cobra.CheckErr(cmd.MarkFlagRequired("digest"))

	return cmd
}
