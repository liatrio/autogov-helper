package metadata

import (
	"fmt"
	"os"
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

			opts.Version = fmt.Sprintf("%s-%s", shortSHA, ctx.RunNumber)
			opts.Created = now
			opts.Type = "https://in-toto.io/attestation/github-workflow/v0.2"
			opts.Repository = ctx.Repository
			opts.RepositoryID = ctx.RepositoryID
			opts.GitHubServerURL = ctx.ServerURL
			opts.Owner = ctx.RepositoryOwner
			opts.OwnerID = ctx.RepositoryOwnerID
			opts.OS = ctx.Runner.OS
			opts.Arch = ctx.Runner.Arch
			opts.Environment = ctx.Runner.Environment
			opts.WorkflowRefPath = ctx.WorkflowRef
			opts.Inputs = ctx.Inputs
			opts.Branch = ctx.RefName
			opts.Event = ctx.EventName
			opts.RunNumber = ctx.RunNumber
			opts.RunID = ctx.RunID
			opts.Status = ctx.JobStatus
			opts.TriggeredBy = ctx.Actor
			opts.Organization = ctx.RepositoryOwner
			opts.SHA = ctx.SHA
			opts.Permissions = map[string]string{
				"id-token":     "write",
				"attestations": "write",
				"packages":     "write",
				"contents":     "read",
			}

			if startTime, err := time.Parse(time.RFC3339, ctx.Event.WorkflowRun.CreatedAt); err == nil {
				opts.StartedAt = startTime
			}
			opts.CompletedAt = now

			if commitTime, err := time.Parse(time.RFC3339, ctx.Event.HeadCommit.Timestamp); err == nil {
				opts.Timestamp = commitTime
			}

			if opts.PolicyRef == "" {
				opts.PolicyRef = "https://github.com/liatrio/demo-gh-autogov-policy-library"
			}

			if len(opts.ControlIds) == 0 {
				opts.ControlIds = []string{
					fmt.Sprintf("%s-PROVENANCE-001", ctx.RepositoryOwner),
					fmt.Sprintf("%s-SBOM-002", ctx.RepositoryOwner),
					fmt.Sprintf("%s-METADATA-003", ctx.RepositoryOwner),
				}
			}

			if buildType == "blob" {
				if opts.SubjectPath == "" {
					return fmt.Errorf("subject-path is required for blob type")
				}
				subjectPath := opts.SubjectPath
				if _, err := os.Stat(subjectPath); err != nil {
					return fmt.Errorf("failed to read subject file: %w", err)
				}
				opts.SubjectPath = subjectPath
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
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject")
	flags.StringVar(&opts.PolicyRef, "policy-ref", "", "Reference to the policy being enforced")
	flags.StringSliceVar(&opts.ControlIds, "control-ids", nil, "Control IDs being enforced")
	flags.StringVar(&opts.SubjectPath, "subject-path", "", "Path to the subject (required for blob type)")
	flags.StringVar(&buildType, "type", "container-image", "Type of build (container-image or blob)")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout)")
	cobra.CheckErr(cmd.MarkFlagRequired("subject-name"))
	cobra.CheckErr(cmd.MarkFlagRequired("digest"))

	return cmd
}
