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
			if len(ctx.SHA) >= 7 {
				shortSHA = ctx.SHA[:7]
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
			opts.RepositoryID = ctx.RepositoryID
			opts.GitHubServerURL = ctx.ServerURL

			// Set owner details
			opts.Owner = ctx.RepositoryOwner
			opts.OwnerID = ctx.RepositoryOwnerID

			// Set runner details
			opts.OS = ctx.Runner.OS
			opts.Arch = ctx.Runner.Arch
			opts.Environment = ctx.Runner.Environment

			// Set workflow details
			opts.WorkflowRefPath = ctx.WorkflowRef
			opts.Inputs = ctx.Inputs
			opts.Branch = ctx.RefName
			opts.Event = ctx.EventName

			// Set job details
			opts.RunNumber = ctx.RunNumber
			opts.RunID = ctx.RunID
			opts.Status = ctx.JobStatus
			opts.TriggeredBy = ctx.Actor
			if startTime, err := time.Parse(time.RFC3339, ctx.Event.WorkflowRun.CreatedAt); err == nil {
				opts.StartedAt = startTime
			}
			opts.CompletedAt = now

			// Set organization details
			opts.Organization = ctx.RepositoryOwner

			// Set commit details
			opts.SHA = ctx.SHA

			// Set build details
			opts.BuildType = buildType
			opts.PermissionType = "github-workflow"

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
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject (required for container-image type, defaults to filename for blob type)")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject")
	flags.StringVar(&opts.SubjectPath, "subject-path", "", "Path to the subject (required for blob type)")
	flags.StringVar(&buildType, "type", "container-image", "Type of build (container-image or blob)")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout)")
	cobra.CheckErr(cmd.MarkFlagRequired("digest"))

	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if buildType == "blob" && opts.SubjectPath == "" {
			return fmt.Errorf("subject-path is required for blob type")
		}
		return nil
	}

	return cmd
}
