package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"autogov-helper/internal/attestation"
	"autogov-helper/internal/types"
	"autogov-helper/internal/util/fileutil"

	"github.com/spf13/cobra"
)

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "autogov-helper",
		Short: "GitHub Actions attestation utilities",
		Long:  "GitHub Actions attestation utilities for generating attestations",
	}

	cmd.AddCommand(
		newMetadataCommand(),
		newDepscanCommand(),
	)

	return cmd
}

func newMetadataCommand() *cobra.Command {
	var opts attestation.MetadataOptions
	var outputFile string
	var artifactType string

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate metadata attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Set artifact type
			switch artifactType {
			case "image":
				opts.Type = types.ArtifactTypeContainerImage
			case "blob":
				opts.Type = types.ArtifactTypeBlob
			default:
				return fmt.Errorf("invalid type %q, must be 'image' or 'blob'", artifactType)
			}

			// Load GitHub context
			ctx, err := attestation.LoadGitHubContext()
			if err != nil {
				return fmt.Errorf("failed to load GitHub context: %w", err)
			}

			// Set GitHub context fields
			opts.Repository = ctx.Repository
			opts.RepositoryID = ctx.RepositoryID
			opts.GitHubServerURL = ctx.ServerURL
			opts.Owner = ctx.RepositoryOwner
			opts.OwnerID = ctx.RepositoryOwnerID
			opts.OS = ctx.Runner.OS
			opts.Arch = ctx.Runner.Arch
			opts.Environment = ctx.Runner.Environment
			opts.WorkflowRefPath = ctx.WorkflowRef
			opts.Branch = ctx.RefName
			opts.Event = ctx.EventName
			opts.RunNumber = ctx.RunNumber
			opts.RunID = ctx.RunID
			opts.Status = ctx.JobStatus
			opts.TriggeredBy = ctx.Actor
			opts.SHA = ctx.SHA
			opts.OrgName = ctx.Organization.Name
			opts.Inputs = ctx.Inputs

			// Set timestamps from event data
			if ctx.Event.WorkflowRun.CreatedAt != "" {
				startTime, err := time.Parse(time.RFC3339, ctx.Event.WorkflowRun.CreatedAt)
				if err == nil {
					opts.StartedAt = startTime.UTC()
				} else {
					// If we can't parse the workflow run creation time, use current time
					opts.StartedAt = time.Now().UTC()
				}
			} else {
				// If no workflow run creation time is available, use current time
				opts.StartedAt = time.Now().UTC()
			}

			// Set completed time to now
			opts.CompletedAt = time.Now().UTC()

			// Set commit timestamp if available
			if ctx.Event.HeadCommit.Timestamp != "" {
				commitTime, err := time.Parse(time.RFC3339, ctx.Event.HeadCommit.Timestamp)
				if err == nil {
					opts.Timestamp = commitTime.UTC()
				} else {
					// If we can't parse the commit timestamp, use current time
					opts.Timestamp = time.Now().UTC()
				}
			} else {
				// If no commit timestamp is available, use current time
				opts.Timestamp = time.Now().UTC()
			}

			// Set version based on SHA and run number
			if opts.SHA != "" && opts.RunNumber != "" {
				shortSHA := opts.SHA
				if len(shortSHA) > 7 {
					shortSHA = shortSHA[:7]
				}
				opts.Version = fmt.Sprintf("%s-%s", shortSHA, opts.RunNumber)
			}

			// Set created time to now if not set
			if opts.Created.IsZero() {
				opts.Created = time.Now().UTC()
			}

			// Set policy reference and control IDs
			opts.PolicyRef = "https://github.com/liatrio/demo-gh-autogov-policy-library"
			if opts.Owner != "" {
				opts.ControlIds = []string{
					"liatrio-PROVENANCE-001",
					"liatrio-SBOM-002",
					"liatrio-METADATA-003",
				}
			}

			// Set permissions based on type
			opts.Permissions = map[string]string{
				"id-token":     "write",
				"attestations": "write",
				"contents":     "read",
			}
			if opts.Type == types.ArtifactTypeContainerImage {
				opts.Permissions["packages"] = "write"
				// Append digest to fullName if not already present
				if !strings.Contains(opts.FullName, "@sha256:") {
					opts.FullName = fmt.Sprintf("%s@%s", opts.FullName, opts.Digest)
				}
			} else {
				opts.Permissions["packages"] = "none"
			}

			// Validate required fields
			switch opts.Type {
			case types.ArtifactTypeContainerImage:
				if opts.FullName == "" {
					return fmt.Errorf("--subject-name is required for image type")
				}
				if opts.Digest == "" {
					return fmt.Errorf("--subject-digest is required for image type")
				}
				// Parse registry from subject-name if it contains a hostname
				if parts := strings.Split(opts.FullName, "/"); len(parts) > 2 && strings.Contains(parts[0], ".") {
					opts.Registry = parts[0]
				}
			case types.ArtifactTypeBlob:
				if opts.SubjectPath == "" {
					return fmt.Errorf("--subject-path is required for blob type")
				}
				// Calculate digest for blob if not provided
				if opts.Digest == "" {
					digest, err := fileutil.CalculateDigest(opts.SubjectPath)
					if err != nil {
						return fmt.Errorf("failed to calculate digest: %w", err)
					}
					opts.Digest = digest
				}
			}

			return attestation.GenerateMetadata(opts, outputFile)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.SubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&opts.FullName, "subject-name", "", "Name of the subject being attested (required for image type)")
	flags.StringVar(&opts.Digest, "subject-digest", "", "SHA256 digest of the subject (required for image type)")
	flags.StringVar(&outputFile, "output", "", "Output file")
	flags.StringVar(&artifactType, "type", "image", "Type of build (image or blob)")

	return cmd
}

func newDepscanCommand() *cobra.Command {
	var opts attestation.DepscanOptions
	var outputFile string
	var artifactType string

	cmd := &cobra.Command{
		Use:   "depscan",
		Short: "Generate dependency scan attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch artifactType {
			case "image":
				opts.Type = types.ArtifactTypeContainerImage
				if opts.SubjectName == "" {
					return fmt.Errorf("--subject-name is required for image type")
				}
				if opts.Digest == "" {
					return fmt.Errorf("--digest is required for image type")
				}
			case "blob":
				opts.Type = types.ArtifactTypeBlob
				if opts.SubjectPath == "" {
					return fmt.Errorf("--subject-path is required for blob type")
				}
				// Calculate digest for blob if not provided
				if opts.Digest == "" {
					digest, err := fileutil.CalculateDigest(opts.SubjectPath)
					if err != nil {
						return fmt.Errorf("failed to calculate digest: %w", err)
					}
					opts.Digest = digest
				}
			default:
				return fmt.Errorf("invalid type %q, must be 'image' or 'blob'", artifactType)
			}

			return attestation.GenerateDepscan(opts, outputFile)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.ResultsPath, "results-path", "", "Path to Grype results JSON file")
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject being scanned (required for image type)")
	flags.StringVar(&opts.SubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject being scanned (required for container images, auto-calculated for blobs)")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&artifactType, "type", "image", "Type of artifact (image or blob)")
	cobra.CheckErr(cmd.MarkFlagRequired("results-path"))

	return cmd
}
