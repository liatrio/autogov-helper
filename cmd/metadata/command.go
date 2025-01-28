package metadata

import (
	"fmt"
	"os"
	"time"

	metadata "gh-attest-util/internal/attestation/metadata"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	var opts metadata.Options
	var outputFile string
	var subjectName string
	var subjectPath string
	var subjectDigest string
	var artifactType string

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate metadata predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Set repository data
			opts.Repository = os.Getenv("GITHUB_REPOSITORY")
			opts.RepositoryID = os.Getenv("GITHUB_REPOSITORY_ID")
			opts.GitHubServerURL = os.Getenv("GITHUB_SERVER_URL")

			// Set owner data
			opts.Owner = os.Getenv("GITHUB_REPOSITORY_OWNER")
			opts.OwnerID = os.Getenv("GITHUB_REPOSITORY_OWNER_ID")

			// Set runner data
			opts.OS = os.Getenv("RUNNER_OS")
			opts.Arch = os.Getenv("RUNNER_ARCH")
			opts.Environment = os.Getenv("RUNNER_ENVIRONMENT")

			// Set workflow data
			opts.WorkflowRefPath = os.Getenv("GITHUB_WORKFLOW_REF")
			opts.Branch = os.Getenv("GITHUB_REF_NAME")
			opts.Event = os.Getenv("GITHUB_EVENT_NAME")

			// Set job data
			opts.RunNumber = os.Getenv("GITHUB_RUN_NUMBER")
			opts.RunID = os.Getenv("GITHUB_RUN_ID")
			opts.Status = os.Getenv("GITHUB_JOB_STATUS")
			opts.TriggeredBy = os.Getenv("GITHUB_ACTOR")
			if startedAt, err := time.Parse(time.RFC3339, os.Getenv("GITHUB_JOB_STARTED_AT")); err == nil {
				opts.StartedAt = startedAt
			}
			if completedAt, err := time.Parse(time.RFC3339, os.Getenv("GITHUB_JOB_COMPLETED_AT")); err == nil {
				opts.CompletedAt = completedAt
			}

			// Set commit data
			opts.SHA = os.Getenv("GITHUB_SHA")
			if timestamp, err := time.Parse(time.RFC3339, os.Getenv("GITHUB_EVENT_TIMESTAMP")); err == nil {
				opts.Timestamp = timestamp
			}

			// Set organization data
			opts.OrgName = os.Getenv("GITHUB_ORGANIZATION")

			// Set compliance data
			opts.PolicyRef = os.Getenv("POLICY_REF")
			if controlIds := os.Getenv("CONTROL_IDS"); controlIds != "" {
				opts.ControlIds = []string{controlIds}
			}

			// Set security data
			opts.Permissions = map[string]string{
				"id-token":     "write",
				"attestations": "write",
				"contents":     "read",
				"packages":     "read",
			}

			// Set artifact data
			opts.Created = time.Now()
			opts.Version = fmt.Sprintf("%s-%s", opts.SHA, opts.RunNumber)

			// Handle artifact type-specific fields
			switch artifactType {
			case "container-image":
				opts.Type = metadata.ArtifactTypeContainerImage
				if subjectName == "" {
					return fmt.Errorf("subject-name is required for container-image type")
				}
				if subjectDigest == "" {
					return fmt.Errorf("subject-digest is required for container-image type")
				}
				opts.FullName = subjectName
				opts.Digest = subjectDigest
			case "blob":
				opts.Type = metadata.ArtifactTypeBlob
				if subjectPath == "" {
					return fmt.Errorf("subject-path is required for blob type")
				}
				opts.SubjectPath = subjectPath
			default:
				return fmt.Errorf("invalid artifact type: %s", artifactType)
			}

			m, err := metadata.NewFromOptions(opts)
			if err != nil {
				return fmt.Errorf("failed to create metadata: %w", err)
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
	flags.StringVar(&outputFile, "output", "", "Output file")
	flags.StringVar(&subjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&subjectName, "subject-name", "", "Name of the subject being attested (required for container-image type)")
	flags.StringVar(&subjectDigest, "subject-digest", "", "SHA256 digest of the subject (required for container-image type)")
	flags.StringVar(&artifactType, "type", "container-image", "Type of build (container-image or blob)")

	return cmd
}
